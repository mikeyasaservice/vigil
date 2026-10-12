#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../../.." && pwd)"
phase3_dir="$repo_dir/infra/phase3-aws"
bootstrap_dir="$repo_dir/infra/production-qualification/bootstrap"
work_root="${VIGIL_AWS_QUALIFICATION_ROOT:-/tmp/vigil-aws-qualification}"
profile="${AWS_PROFILE:-pulumi}"
region="${AWS_REGION:-us-east-1}"
account_id="${VIGIL_AWS_ACCOUNT_ID:?set VIGIL_AWS_ACCOUNT_ID to the authorized qualification account}"
trusted_principal="${VIGIL_AWS_TRUSTED_PRINCIPAL_ARN:?set VIGIL_AWS_TRUSTED_PRINCIPAL_ARN to the approved deployer role}"
control_plane_cidr="${VIGIL_CONTROL_PLANE_CIDR:?set VIGIL_CONTROL_PLANE_CIDR to the qualifying host /32}"

mkdir -p "$work_root"
chmod 700 "$work_root"
if [[ ! -s "$work_root/passphrase" ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(64))' >"$work_root/passphrase"
fi
export PULUMI_CONFIG_PASSPHRASE
PULUMI_CONFIG_PASSPHRASE="$(cat "$work_root/passphrase")"
export AWS_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true

configure_tenant_profiles() {
  local source_config="${AWS_CONFIG_FILE:-${HOME}/.aws/config}" generated_config="$work_root/aws-config"
  [[ -r "$source_config" ]] || { echo "AWS config is not readable: $source_config" >&2; return 1; }
  cp "$source_config" "$generated_config"
  for tenant in a b; do
    local role external
    role="$(jq -er --arg tenant "$tenant" '.roleArns[$tenant]' "$work_root/bootstrap/outputs.json")"
    external="$(jq -er --arg tenant "$tenant" '.externalIds[$tenant]' "$work_root/bootstrap/outputs.json")"
    cat >>"$generated_config" <<EOF

[profile vigil-tenant-$tenant]
role_arn = $role
source_profile = $profile
external_id = $external
region = $region
EOF
  done
  chmod 600 "$generated_config"
  export AWS_CONFIG_FILE="$generated_config"
}

expires_at() {
  python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(hours=48)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
}

pulumi_at() {
  local root="$1" source="$2"; shift 2
  PULUMI_HOME="$root/pulumi-home" PULUMI_BACKEND_URL="file://$root/state" pulumi --cwd "$source" "$@"
}

prepare_source() {
  local source="$1" destination="$2"
  mkdir -p "$destination"
  rsync -a --delete --exclude 'Pulumi.*.yaml' "$source/" "$destination/"
}

bootstrap() {
	local root="$work_root/bootstrap" source expiry
	source="$root/source"
  expiry="$(expires_at)"
  mkdir -p "$root/pulumi-home" "$root/state"
  prepare_source "$bootstrap_dir" "$source"
  pulumi_at "$root" "$source" login "file://$root/state" >/dev/null
  pulumi_at "$root" "$source" stack select qualification --create --non-interactive
  pulumi_at "$root" "$source" config set vigil-production-qualification-bootstrap:accountId "$account_id" --non-interactive
  pulumi_at "$root" "$source" config set vigil-production-qualification-bootstrap:region "$region" --non-interactive
  pulumi_at "$root" "$source" config set vigil-production-qualification-bootstrap:trustedPrincipalArn "$trusted_principal" --non-interactive
  pulumi_at "$root" "$source" config set vigil-production-qualification-bootstrap:expiresAt "$expiry" --non-interactive
  pulumi_at "$root" "$source" preview --diff --non-interactive --save-plan "$root/plan.json"
  pulumi_at "$root" "$source" up --yes --non-interactive --plan "$root/plan.json"
  pulumi_at "$root" "$source" stack output --show-secrets --json >"$root/outputs.json"
  chmod 600 "$root/outputs.json"
}

bootstrap_offboard() {
  local root="$work_root/bootstrap" source="$work_root/bootstrap/source"
  [[ -s "$root/outputs.json" ]] || { echo "bootstrap outputs are missing" >&2; return 1; }
  cp "$root/outputs.json" "$root/outputs.pre-offboard.json"
  chmod 600 "$root/outputs.pre-offboard.json"
  pulumi_at "$root" "$source" login "file://$root/state" >/dev/null
  pulumi_at "$root" "$source" stack select qualification --non-interactive
  pulumi_at "$root" "$source" destroy --yes --non-interactive
  AWS_CONFIG_FILE="${HOME}/.aws/config" AWS_PROFILE="$profile" \
    python3 "$script_dir/bootstrap-offboard-verify.py"
}

render_tenant() {
	local tenant="$1" cidr_octet="$2" root deployment
	root="$work_root/tenant-$tenant"
	deployment="deployment-qual-$tenant"
  local tenant_id="tenant-qual-$tenant" role external expiry infra_digest
  [[ -s "$work_root/bootstrap/outputs.json" ]] || { echo "bootstrap outputs are missing" >&2; return 1; }
  role="$(jq -er --arg tenant "$tenant" '.roleArns[$tenant]' "$work_root/bootstrap/outputs.json")"
  external="$(jq -er --arg tenant "$tenant" '.externalIds[$tenant]' "$work_root/bootstrap/outputs.json")"
  expiry="$(jq -er .expiresAt "$work_root/bootstrap/outputs.json")"
  infra_digest="$(cd "$phase3_dir" && GOCACHE=/private/tmp/autobot-go-cache go run ./cmd/artifact-digest .)"
  mkdir -p "$root/pulumi-home" "$root/state" "$root/trust" "$root/workspace"
  prepare_source "$phase3_dir" "$root/source"
  jq --arg tenant "$tenant_id" --arg deployment "$deployment" \
    --arg binding "local:aws-qualification-$tenant" --arg network "local:aws-network-$tenant" \
    --arg state "local:aws-state-$tenant" --arg infra "$infra_digest" \
    '.tenant_id=$tenant | .deployment_id=$deployment |
     .incarnation=(if $tenant == "tenant-qual-a" then "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" else "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" end) |
     .placement.account_binding_ref=$binding | .placement.network_binding_ref=$network |
     .placement.state_binding_ref=$state | .releases.infrastructure.digest_ref=$infra' \
    "$repo_dir/docs/architecture/contracts/deployment-manifest.example.json" >"$root/manifest.json"
  jq -n --arg tenant "$tenant_id" --arg deployment "$deployment" --arg role "$role" --arg external "$external" \
    --arg region "$region" --arg account "$account_id" --arg expiry "$expiry" --arg api_cidr "$control_plane_cidr" \
    --arg kube_profile "vigil-tenant-$tenant" \
    --arg root "$root" --arg source "$phase3_dir" --arg octet "$cidr_octet" \
    '{execution_profile:"aws",localstack_endpoint:"",binding_ref:("local:aws-qualification-"+$tenant[-1:]),
      tenant_id:$tenant,deployment_id:$deployment,account_id:$account,role_arn:$role,external_id:$external,
      kubeconfig_credential_profile:$kube_profile,region:$region,
      network_binding_ref:("local:aws-network-"+$tenant[-1:]),state_binding_ref:("local:aws-state-"+$tenant[-1:]),
      state_backend_url:("file://"+$root+"/state"),secrets_provider:"passphrase",pulumi_home:($root+"/pulumi-home"),
      workspace_root:($root+"/workspace"),receipt_private_key_path:($root+"/trust/receipt.key"),
      infrastructure_source_path:$source,reconciler_spiffe_id:("spiffe://autobot.internal/reconciler/"+$tenant),
      management_base_url:"https://management.autobot.internal",management_server_name:"management.autobot.internal",
      management_ca_path:($root+"/trust/ca.pem"),management_client_cert_path:($root+"/trust/reconciler.crt"),
      management_client_key_path:($root+"/trust/reconciler.key"),permitted_availability_zones:[($region+"a"),($region+"b")],
      vpc_cidr:("10."+$octet+".0.0/16"),public_subnet_cidrs:[("10."+$octet+".0.0/24"),("10."+$octet+".1.0/24")],
      private_subnet_cidrs:[("10."+$octet+".16.0/20"),("10."+$octet+".32.0/20")],public_ingress_cidrs:[],
      control_plane_access_cidrs:[$api_cidr],resource_expires_at:$expiry,lifecycle_state:"active"}' >"$root/binding.json"
  chmod 600 "$root/binding.json"
}

tenant_command() {
	local tenant="$1" command="$2" root source
	root="$work_root/tenant-$tenant"
	source="$root/source"
  pulumi_at "$root" "$source" login "file://$root/state" >/dev/null
  pulumi_at "$root" "$source" stack select "tenant-$tenant" --create --non-interactive
  pulumi_at "$root" "$source" config set vigil-managed-dedicated-aws:manifestPath "$root/manifest.json" --non-interactive
  pulumi_at "$root" "$source" config set vigil-managed-dedicated-aws:bindingPath "$root/binding.json" --non-interactive
  case "$command" in
    preview) pulumi_at "$root" "$source" preview --diff --non-interactive --save-plan "$root/plan.json" ;;
    apply)
      [[ -s "$root/plan.json" ]] || { echo "saved plan missing for tenant $tenant" >&2; return 1; }
      pulumi_at "$root" "$source" up --yes --non-interactive --plan "$root/plan.json"
      pulumi_at "$root" "$source" stack output --json >"$root/outputs.json"
      chmod 600 "$root/outputs.json"
      ;;
    reconcile)
      # The Pulumi EKS component resolves some child-role properties only during
      # creation. After a partial update, review the refreshed delta and apply it
      # without strict unknown-value equality from the original saved plan.
      pulumi_at "$root" "$source" refresh --yes --non-interactive
      pulumi_at "$root" "$source" preview --diff --non-interactive | tee "$root/reconcile-preview.txt"
      pulumi_at "$root" "$source" up --yes --non-interactive
      pulumi_at "$root" "$source" stack output --json >"$root/outputs.json"
      chmod 600 "$root/outputs.json" "$root/reconcile-preview.txt"
      ;;
    offboard)
	  cp "$root/outputs.json" "$root/outputs.pre-offboard.json"
	  chmod 600 "$root/outputs.pre-offboard.json"
      jq '.lifecycle_state="offboarding"' "$root/binding.json" >"$root/binding.next.json"
      mv "$root/binding.next.json" "$root/binding.json"; chmod 600 "$root/binding.json"
      pulumi_at "$root" "$source" up --yes --non-interactive
      pulumi_at "$root" "$source" destroy --yes --non-interactive
	  python3 "$script_dir/offboard-verify.py" "$tenant"
      ;;
  esac
}

repair_pending_coredns() {
  local tenant="$1" root source cluster parent_urn provider_urn asg_name
  root="$work_root/tenant-$tenant"
  source="$root/source"
  cluster="$(aws --profile "vigil-tenant-$tenant" eks list-clusters \
    --query "clusters[?starts_with(@, 'vigil-deployment-qual-$tenant-eks-eksCluster-')] | [0]" --output text)"
  [[ -n "$cluster" && "$cluster" != "None" ]] || { echo "tenant $tenant EKS cluster was not found" >&2; return 1; }
  parent_urn="urn:pulumi:tenant-$tenant::vigil-managed-dedicated-aws::vigil:managed:DedicatedDeployment\$eks:index:Cluster::vigil-deployment-qual-$tenant-eks"
  provider_urn="urn:pulumi:tenant-$tenant::vigil-managed-dedicated-aws::pulumi:providers:aws::tenant-aws"
  asg_name="$(aws --profile "vigil-tenant-$tenant" autoscaling describe-auto-scaling-groups \
    --query "AutoScalingGroups[?starts_with(AutoScalingGroupName, 'vigil-deployment-qual-$tenant-eks-')].AutoScalingGroupName | [0]" --output text)"
  [[ -n "$asg_name" && "$asg_name" != "None" ]] || { echo "tenant $tenant autoscaling group was not found" >&2; return 1; }
  pulumi_at "$root" "$source" import aws:eks/addon:Addon "vigil-deployment-qual-$tenant-eks-coredns" \
    "$cluster:coredns" --parent "cluster=$parent_urn" --provider "tenant=$provider_urn" \
    --protect=false --generate-code=false --yes --non-interactive
  pulumi_at "$root" "$source" import aws:autoscaling/group:Group "vigil-deployment-qual-$tenant-eks" \
    "$asg_name" --parent "cluster=$parent_urn" --provider "tenant=$provider_urn" \
    --protect=false --generate-code=false --yes --non-interactive
}

case "${1:-preview}" in
  bootstrap) bootstrap ;;
  bootstrap-offboard) bootstrap_offboard ;;
  prepare) bootstrap; render_tenant a 64; render_tenant b 80 ;;
  stage) configure_tenant_profiles; render_tenant a 64; render_tenant b 80 ;;
  repair-a-coredns) configure_tenant_profiles; repair_pending_coredns a ;;
  preview) bootstrap; render_tenant a 64; render_tenant b 80; tenant_command a preview; tenant_command b preview ;;
  apply) configure_tenant_profiles; tenant_command a apply; tenant_command b apply ;;
  reconcile) configure_tenant_profiles; tenant_command a reconcile; tenant_command b reconcile ;;
  byoc-qualify) "$script_dir/byoc-qualify.sh" qualify ;;
  byoc-offboard) "$script_dir/byoc-qualify.sh" offboard ;;
  offboard-a) configure_tenant_profiles; tenant_command a offboard ;;
  offboard-b) configure_tenant_profiles; tenant_command b offboard ;;
  offboard) configure_tenant_profiles; tenant_command a offboard; tenant_command b offboard; bootstrap_offboard ;;
  *) echo "usage: $0 [bootstrap|bootstrap-offboard|prepare|stage|repair-a-coredns|preview|apply|reconcile|byoc-qualify|byoc-offboard|offboard-a|offboard-b|offboard]" >&2; exit 2 ;;
esac
