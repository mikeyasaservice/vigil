#!/usr/bin/env bash
set -euo pipefail

context="${KIND_CONTEXT:-kind-vigil-phase2}"
kubectl_args=(--context "$context")
if [[ -n "${KUBECONFIG:-}" ]]; then
  kubectl_args=(--kubeconfig "$KUBECONFIG")
fi

worker_a="${WORKER_A_POD:-$(kubectl "${kubectl_args[@]}" -n vigil-tenant-a get pod -l app.kubernetes.io/component=agent-worker -o jsonpath='{.items[0].metadata.name}')}"
worker_b="${WORKER_B_POD:-$(kubectl "${kubectl_args[@]}" -n vigil-tenant-b get pod -l app.kubernetes.io/component=agent-worker -o jsonpath='{.items[0].metadata.name}')}"
[[ -n "$worker_a" && -n "$worker_b" ]] || { echo "both managed worker pods must exist" >&2; exit 1; }

service_host() {
  printf '%s.%s.svc.cluster.local' "$1" "$2"
}

require_ready_service() {
  local namespace="$1" service="$2" ready
  kubectl "${kubectl_args[@]}" -n "$namespace" get service "$service" >/dev/null
  ready="$(kubectl "${kubectl_args[@]}" -n "$namespace" get endpointslice \
    -l "kubernetes.io/service-name=$service" \
    -o jsonpath='{range .items[*].endpoints[*]}{.conditions.ready}{"\n"}{end}' | grep -c '^true$' || true)"
  if [[ "$ready" -lt 1 ]]; then
    echo "service $namespace/$service has no ready endpoint" >&2
    exit 1
  fi
}

# Resolve first, then make one TCP attempt. Exit 20 is reserved for a Cilium-style
# drop. DNS failures and connection refusals are different failures and cannot
# count as isolation evidence.
probe_js='import dns from "node:dns"; import net from "node:net";
const [host, rawPort] = process.argv.slice(1); const port = Number(rawPort);
dns.lookup(host, {all:true}, (dnsError, addresses) => {
  if (dnsError || addresses.length === 0) { console.error(`DNS_ERROR ${dnsError?.code ?? "EMPTY"}`); process.exit(21); }
  const socket = net.createConnection({host, port});
  const timer = setTimeout(() => { socket.destroy(); console.error(`TIMEOUT ${addresses.map(a => a.address).join(",")}`); process.exit(20); }, 3000);
  socket.once("connect", () => { clearTimeout(timer); console.log(`CONNECTED ${socket.remoteAddress}:${socket.remotePort}`); socket.destroy(); process.exit(0); });
  socket.once("error", error => { clearTimeout(timer); console.error(`CONNECT_ERROR ${error.code ?? "UNKNOWN"}`); process.exit(22); });
});'

probe() {
  local namespace="$1" pod="$2" host="$3" port="$4"
  kubectl "${kubectl_args[@]}" -n "$namespace" exec "$pod" -c agent-worker -- \
    node --input-type=module -e "$probe_js" -- "$host" "$port"
}

expect_allowed() {
  local namespace="$1" pod="$2" host="$3" port="$4" label="$5" output
  if ! output="$(probe "$namespace" "$pod" "$host" "$port" 2>&1)"; then
    echo "allowed probe failed ($label): $output" >&2
    exit 1
  fi
  echo "allowed: $label ($output)"
}

expect_denied() {
  local namespace="$1" pod="$2" host="$3" port="$4" label="$5" output rc
  set +e
  output="$(probe "$namespace" "$pod" "$host" "$port" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 20 ]]; then
    echo "denied probe was not a policy drop ($label, rc=$rc): $output" >&2
    exit 1
  fi
  echo "denied: $label ($output)"
}

http_positive() {
  local namespace="$1" selector="$2" container="$3" url="$4" label="$5" pod output
  pod="$(kubectl "${kubectl_args[@]}" -n "$namespace" get pod -l "$selector" -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$pod" ]] || { echo "positive-control pod missing ($label)" >&2; exit 1; }
  if ! output="$(kubectl "${kubectl_args[@]}" -n "$namespace" exec "$pod" -c "$container" -- \
    python -c 'import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=5).status)' "$url" 2>&1)"; then
    echo "positive HTTP control failed ($label): $output" >&2
    exit 1
  fi
  [[ "$output" == *"200"* ]] || { echo "positive HTTP control returned non-200 ($label): $output" >&2; exit 1; }
  echo "allowed: $label ($output)"
}

localstack_count() {
  local namespace="$1" kind="$2"
  if [[ "$kind" == secrets ]]; then
    kubectl "${kubectl_args[@]}" -n "$namespace" exec deploy/phase2-localstack -- \
      awslocal secretsmanager list-secrets --query 'length(SecretList)' --output text
  else
    kubectl "${kubectl_args[@]}" -n "$namespace" exec deploy/phase2-localstack -- \
      awslocal s3api list-buckets --query 'length(Buckets)' --output text
  fi
}

for tenant in a b; do
  namespace="vigil-tenant-$tenant"
  release="tenant-$tenant-vigil"
  for component in backend connector postgres reasoner redis security; do
    require_ready_service "$namespace" "$release-$component"
  done
  require_ready_service "$namespace" "$namespace-localstack-service"
  require_ready_service "$namespace" "$namespace-model-service"
done

secret_before=()
bucket_before=()
tenant_index=0
for tenant in a b; do
  namespace="vigil-tenant-$tenant"
  localstack_host="$(service_host "$namespace-localstack-service" "$namespace")"
  model_host="$(service_host "$namespace-model-service" "$namespace")"
  http_positive "$namespace" "app.kubernetes.io/component=connector" connector \
    "http://$localstack_host:4566/_localstack/health" "$tenant connector to tenant-local secret/object endpoint"
  http_positive "$namespace" "app.kubernetes.io/component=reasoner" reasoner \
    "http://$model_host:8446/health" "$tenant reasoner to approved model endpoint"
  secret_before[$tenant_index]="$(localstack_count "$namespace" secrets)"
  bucket_before[$tenant_index]="$(localstack_count "$namespace" buckets)"
  tenant_index=$((tenant_index + 1))
done

for tenant in a b; do
  namespace="vigil-tenant-$tenant"
  worker_var="worker_$tenant"
  worker="${!worker_var}"
  release="tenant-$tenant-vigil"
  expect_allowed "$namespace" "$worker" "$(service_host "$release-redis" "$namespace")" 6379 "$tenant worker to tenant-local queue"
  expect_allowed "$namespace" "$worker" "$(service_host "$release-postgres" "$namespace")" 5432 "$tenant worker to restricted ledger"
  expect_allowed "$namespace" "$worker" "$(service_host "$release-security" "$namespace")" 8443 "$tenant worker to capability gateway"
  expect_allowed "$namespace" "$worker" "$(service_host "$release-reasoner" "$namespace")" 8445 "$tenant worker to pinned reasoner"
  expect_denied "$namespace" "$worker" "$(service_host "$release-connector" "$namespace")" 8444 "$tenant worker direct to connector"
  expect_denied "$namespace" "$worker" "$(service_host "$release-backend" "$namespace")" 6987 "$tenant worker direct to backend"
  expect_denied "$namespace" "$worker" "$(service_host "$namespace-localstack-service" "$namespace")" 4566 "$tenant worker direct to secret/object endpoint"
  expect_denied "$namespace" "$worker" "$(service_host "$namespace-model-service" "$namespace")" 8446 "$tenant worker direct to model endpoint"
done

for source in a b; do
  if [[ "$source" == a ]]; then target=b; else target=a; fi
  namespace="vigil-tenant-$source"
  target_namespace="vigil-tenant-$target"
  worker_var="worker_$source"
  worker="${!worker_var}"
  release="tenant-$target-vigil"
  expect_denied "$namespace" "$worker" "$(service_host "$release-redis" "$target_namespace")" 6379 "$source worker to $target queue"
  expect_denied "$namespace" "$worker" "$(service_host "$release-postgres" "$target_namespace")" 5432 "$source worker to $target database"
  expect_denied "$namespace" "$worker" "$(service_host "$release-security" "$target_namespace")" 8443 "$source worker to $target gateway"
  expect_denied "$namespace" "$worker" "$(service_host "$release-reasoner" "$target_namespace")" 8445 "$source worker to $target reasoner"
  expect_denied "$namespace" "$worker" "$(service_host "$release-connector" "$target_namespace")" 8444 "$source worker to $target connector"
  expect_denied "$namespace" "$worker" "$(service_host "$release-backend" "$target_namespace")" 6987 "$source worker to $target backend"
  expect_denied "$namespace" "$worker" "$(service_host "$target_namespace-localstack-service" "$target_namespace")" 4566 "$source worker to $target secret/object endpoint"
  expect_denied "$namespace" "$worker" "$(service_host "$target_namespace-model-service" "$target_namespace")" 8446 "$source worker to $target model endpoint"
done

tenant_index=0
for tenant in a b; do
  namespace="vigil-tenant-$tenant"
  [[ "$(localstack_count "$namespace" secrets)" == "${secret_before[$tenant_index]}" ]] || {
    echo "tenant-$tenant secret state changed during denied probes" >&2; exit 1;
  }
  [[ "$(localstack_count "$namespace" buckets)" == "${bucket_before[$tenant_index]}" ]] || {
    echo "tenant-$tenant object-store state changed during denied probes" >&2; exit 1;
  }
  tenant_index=$((tenant_index + 1))
done

echo "phase2 network isolation probes passed with ready destinations, positive controls, and unchanged cloud state"
