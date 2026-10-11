#!/usr/bin/env bash
set -euo pipefail

: "${WORKER_A_POD:?set WORKER_A_POD to the tenant A worker pod}"
: "${WORKER_B_POD:?set WORKER_B_POD to the tenant B worker pod}"
context="${KIND_CONTEXT:-kind-vigil-phase2}"
sink_a="${SINK_A_URL:-http://sink.vigil-tenant-a.svc.cluster.local:8080/healthz}"
sink_b="${SINK_B_URL:-http://sink.vigil-tenant-b.svc.cluster.local:8080/healthz}"
exec_a=(kubectl --context "$context" -n vigil-tenant-a exec "$WORKER_A_POD" -- /bin/sh -c)
exec_b=(kubectl --context "$context" -n vigil-tenant-b exec "$WORKER_B_POD" -- /bin/sh -c)

# Both same-tenant probes must work before a cross-tenant failure counts as evidence.
"${exec_a[@]}" 'test -n "${VIGIL_DEPLOYMENT_ID:-}"'
"${exec_b[@]}" 'test -n "${VIGIL_DEPLOYMENT_ID:-}"'
"${exec_a[@]}" "wget -qO- --timeout=3 '$sink_a' | grep -Eq '200|ok|healthy'"
"${exec_b[@]}" "wget -qO- --timeout=3 '$sink_b' | grep -Eq '200|ok|healthy'"

if "${exec_a[@]}" "wget -qO- --timeout=3 '$sink_b' >/tmp/cross-tenant-response"; then
  echo "tenant-a worker reached tenant-b sink" >&2
  exit 1
fi
if "${exec_b[@]}" "wget -qO- --timeout=3 '$sink_a' >/tmp/cross-tenant-response"; then
  echo "tenant-b worker reached tenant-a sink" >&2
  exit 1
fi
echo "phase2 isolation probe passed: positive controls succeeded and cross-tenant requests were denied"
