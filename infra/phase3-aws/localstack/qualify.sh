#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$project_dir/../.." && pwd)"
work_root="${PHASE3_LOCALSTACK_WORK_ROOT:-/tmp/vigil-phase3-localstack}"
compose=(docker compose -f "$script_dir/compose.yaml")

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_SESSION_TOKEN=test
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export PULUMI_CONFIG_PASSPHRASE="${PULUMI_CONFIG_PASSPHRASE:-vigil-localstack-development-only}"

endpoint() {
  case "$1" in
    a) printf '%s' 'http://127.0.0.1:4566' ;;
    b) printf '%s' 'http://127.0.0.1:4567' ;;
    *) return 2 ;;
  esac
}

await_localstack() {
  local tenant="$1" url attempts=0
  url="$(endpoint "$tenant")/_localstack/health"
  until curl -fsS "$url" >/dev/null; do
    attempts=$((attempts + 1))
    if (( attempts >= 60 )); then
      echo "LocalStack tenant-$tenant did not become healthy" >&2
      return 1
    fi
    sleep 1
  done
}

render_inputs() {
	local tenant="$1" port="$2" cidr_octet="$3"
	local deployment="deployment-local-$tenant"
	local tenant_id="tenant-$tenant" destination="$work_root/$tenant"
	local trust_root="$work_root/trust"
	mkdir -p "$destination/pulumi-home" "$destination/workspace" "$destination/state" "$destination/source"
	local source_digest
	source_digest="$(cd "$project_dir" && go run ./cmd/artifact-digest .)"
	rsync -a --delete --exclude 'Pulumi.*.yaml' "$project_dir/" "$destination/source/"
  jq \
    --arg tenant "$tenant_id" \
    --arg deployment "$deployment" \
    --arg binding "local:phase3-localstack-$tenant" \
    --arg network "local:phase3-network-$tenant" \
    --arg state "local:phase3-state-$tenant" \
	--arg infra "$source_digest" \
    '.tenant_id=$tenant | .deployment_id=$deployment |
     .incarnation=(if $tenant == "tenant-a" then "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" else "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" end) |
     .placement.account_binding_ref=$binding | .placement.network_binding_ref=$network |
	     .placement.state_binding_ref=$state | .releases.infrastructure.digest_ref=$infra' \
    "$repo_dir/docs/architecture/contracts/deployment-manifest.example.json" >"$destination/manifest.json"
  jq -n \
    --arg tenant "$tenant_id" --arg deployment "$deployment" \
    --arg binding "local:phase3-localstack-$tenant" --arg network "local:phase3-network-$tenant" \
    --arg state "local:phase3-state-$tenant" --arg endpoint "http://127.0.0.1:$port" \
    --arg home "$destination/pulumi-home" --arg workspace "$destination/workspace" \
    --arg source "$project_dir" --arg backend "file://$destination/state" \
	--arg receipt_key "$trust_root/receipt-$tenant.key" --arg ca "$trust_root/ca.pem" \
	--arg client_cert "$trust_root/reconciler-$tenant.crt" --arg client_key "$trust_root/reconciler-$tenant.key" \
    --arg vpc "10.$cidr_octet.0.0/16" --arg public_a "10.$cidr_octet.0.0/24" \
    --arg public_b "10.$cidr_octet.1.0/24" --arg private_a "10.$cidr_octet.16.0/20" \
    --arg private_b "10.$cidr_octet.32.0/20" \
    '{execution_profile:"localstack",localstack_endpoint:$endpoint,binding_ref:$binding,
      tenant_id:$tenant,deployment_id:$deployment,account_id:"000000000000",role_arn:"",external_id:"",
      region:"us-east-1",network_binding_ref:$network,state_binding_ref:$state,state_backend_url:$backend,
      secrets_provider:"passphrase",pulumi_home:$home,workspace_root:$workspace,
      receipt_private_key_path:$receipt_key,infrastructure_source_path:$source,
      reconciler_spiffe_id:("spiffe://autobot.local/reconciler/"+$tenant),
      management_base_url:"https://127.0.0.1:8444",management_server_name:"management.autobot.local",
      management_ca_path:$ca,management_client_cert_path:$client_cert,
      management_client_key_path:$client_key,permitted_availability_zones:["us-east-1a","us-east-1b"],
      vpc_cidr:$vpc,public_subnet_cidrs:[$public_a,$public_b],private_subnet_cidrs:[$private_a,$private_b],
      public_ingress_cidrs:[],lifecycle_state:"active"}' >"$destination/binding.json"
}

pulumi_for() {
	local tenant="$1"; shift
	PULUMI_HOME="$work_root/$tenant/pulumi-home" \
		PULUMI_BACKEND_URL="file://$work_root/$tenant/state" \
		pulumi --cwd "$work_root/$tenant/source" "$@"
}

provision() {
  local tenant="$1"
	pulumi_for "$tenant" login "file://$work_root/$tenant/state" >/dev/null
  pulumi_for "$tenant" stack select "tenant-$tenant" --create --non-interactive
  pulumi_for "$tenant" config set vigil-managed-dedicated-aws:manifestPath "$work_root/$tenant/manifest.json" --non-interactive
  pulumi_for "$tenant" config set vigil-managed-dedicated-aws:bindingPath "$work_root/$tenant/binding.json" --non-interactive
  pulumi_for "$tenant" preview --diff --non-interactive --save-plan "$work_root/$tenant/plan.json"
  pulumi_for "$tenant" up --yes --non-interactive --plan "$work_root/$tenant/plan.json"
  pulumi_for "$tenant" stack output --json >"$work_root/$tenant/outputs.json"
}

aws_local() {
  local tenant="$1"; shift
  aws --endpoint-url "$(endpoint "$tenant")" "$@"
}

inventory_digest() {
	local tenant="$1"
	local destination="$work_root/$tenant/inventory.json"
  jq -n \
    --argjson buckets "$(aws_local "$tenant" s3api list-buckets --query 'Buckets[].Name' --output json)" \
    --argjson secrets "$(aws_local "$tenant" secretsmanager list-secrets --query 'SecretList[].Name' --output json)" \
    --argjson queues "$(aws_local "$tenant" sqs list-queues --query 'QueueUrls' --output json)" \
    --argjson vpcs "$(aws_local "$tenant" ec2 describe-vpcs --query 'Vpcs[].VpcId' --output json)" \
    '{buckets:($buckets|sort),secrets:($secrets|sort),queues:($queues|sort),vpcs:($vpcs|sort)}' >"$destination"
  shasum -a 256 "$destination" | awk '{print $1}'
}

test_boundaries() {
  local bucket_a bucket_b before_a before_b after_a after_b
  bucket_a="$(jq -r .evidenceBucket "$work_root/a/outputs.json")"
  bucket_b="$(jq -r .evidenceBucket "$work_root/b/outputs.json")"
  [[ -n "$bucket_a" && -n "$bucket_b" && "$bucket_a" != "$bucket_b" ]]

  printf 'tenant-a-canary' >"$work_root/a/canary.txt"
  printf 'tenant-b-canary' >"$work_root/b/canary.txt"
  aws_local a s3api put-object --bucket "$bucket_a" --key qualification/canary.txt --body "$work_root/a/canary.txt" >/dev/null
  aws_local b s3api put-object --bucket "$bucket_b" --key qualification/canary.txt --body "$work_root/b/canary.txt" >/dev/null
  [[ "$(aws_local a s3api get-object --bucket "$bucket_a" --key qualification/canary.txt "$work_root/a/readback.txt" --query ETag --output text >/dev/null; cat "$work_root/a/readback.txt")" == "tenant-a-canary" ]]
  [[ "$(aws_local b s3api get-object --bucket "$bucket_b" --key qualification/canary.txt "$work_root/b/readback.txt" --query ETag --output text >/dev/null; cat "$work_root/b/readback.txt")" == "tenant-b-canary" ]]

  if aws_local a s3api head-bucket --bucket "$bucket_b" >/dev/null 2>&1; then
    echo "tenant A endpoint could see tenant B bucket" >&2; return 1
  fi
  if aws_local b s3api head-bucket --bucket "$bucket_a" >/dev/null 2>&1; then
    echo "tenant B endpoint could see tenant A bucket" >&2; return 1
  fi

  before_a="$(inventory_digest a)"; before_b="$(inventory_digest b)"
	mkdir -p "$work_root/invalid/pulumi-home" "$work_root/invalid/state" "$work_root/invalid/source"
	rsync -a --delete --exclude 'Pulumi.*.yaml' "$project_dir/" "$work_root/invalid/source/"
	PULUMI_HOME="$work_root/invalid/pulumi-home" PULUMI_BACKEND_URL="file://$work_root/invalid/state" pulumi login "file://$work_root/invalid/state" >/dev/null
	PULUMI_HOME="$work_root/invalid/pulumi-home" PULUMI_BACKEND_URL="file://$work_root/invalid/state" pulumi --cwd "$work_root/invalid/source" stack select invalid --create --non-interactive
	PULUMI_HOME="$work_root/invalid/pulumi-home" PULUMI_BACKEND_URL="file://$work_root/invalid/state" pulumi --cwd "$work_root/invalid/source" config set vigil-managed-dedicated-aws:manifestPath "$work_root/a/manifest.json" --non-interactive
	PULUMI_HOME="$work_root/invalid/pulumi-home" PULUMI_BACKEND_URL="file://$work_root/invalid/state" pulumi --cwd "$work_root/invalid/source" config set vigil-managed-dedicated-aws:bindingPath "$work_root/b/binding.json" --non-interactive
	if PULUMI_HOME="$work_root/invalid/pulumi-home" PULUMI_BACKEND_URL="file://$work_root/invalid/state" pulumi --cwd "$work_root/invalid/source" preview --non-interactive >"$work_root/invalid/cross-target.log" 2>&1; then
    echo "cross-target manifest/binding substitution was accepted" >&2; return 1
  fi
  grep -q "manifest target does not match the trusted binding" "$work_root/invalid/cross-target.log"
  after_a="$(inventory_digest a)"; after_b="$(inventory_digest b)"
  [[ "$before_a" == "$after_a" && "$before_b" == "$after_b" ]]
  echo "PASS: two LocalStack targets provisioned, positive controls succeeded, cross-target access and binding substitution were denied with unchanged inventories"
}

cleanup() {
	local status=0 source tenant
  for tenant in a b; do
    if [[ -d "$work_root/$tenant/state" ]]; then
		if pulumi_for "$tenant" stack select "tenant-$tenant" --non-interactive >/dev/null 2>&1; then
			pulumi_for "$tenant" destroy --yes --non-interactive >/dev/null 2>&1 || status=1
		fi
		for source in "$work_root/$tenant/workspace/deployment-local-$tenant"/*/source; do
			[[ -d "$source" ]] || continue
			PULUMI_HOME="$work_root/$tenant/pulumi-home" \
				PULUMI_BACKEND_URL="file://$work_root/$tenant/state" \
				pulumi --cwd "$source" destroy --stack "deployment-local-$tenant" --yes --non-interactive >/dev/null 2>&1 || status=1
		done
    fi
  done
  "${compose[@]}" down --volumes --remove-orphans
	return "$status"
}

case "${1:-all}" in
  up)
    mkdir -p "$work_root"
    "${compose[@]}" up -d --wait
    await_localstack a; await_localstack b
    render_inputs a 4566 64; render_inputs b 4567 80
    provision a; provision b
    ;;
  test) test_boundaries ;;
  managed)
    mkdir -p "$work_root"
    "${compose[@]}" up -d --wait
    await_localstack a; await_localstack b
    render_inputs a 4566 64; render_inputs b 4567 80
	uv run --no-project --with-requirements "$repo_dir/services/management/requirements.txt" \
		python "$script_dir/management_qualify.py" --repo "$repo_dir" --work-root "$work_root"
	test_boundaries
    ;;
  down) cleanup ;;
  all)
    mkdir -p "$work_root"
    "${compose[@]}" up -d --wait
    await_localstack a; await_localstack b
    render_inputs a 4566 64; render_inputs b 4567 80
    provision a; provision b
    test_boundaries
    ;;
  *) echo "usage: $0 [up|test|managed|down|all]" >&2; exit 2 ;;
esac
