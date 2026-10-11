#!/usr/bin/env bash
set -euo pipefail

: "${WORKER_A_POD:?set WORKER_A_POD to the tenant A worker pod}"
: "${WORKER_B_POD:?set WORKER_B_POD to the tenant B worker pod}"
kubectl --context kind-vigil-phase2 -n vigil-tenant-a exec "$WORKER_A_POD" -- /bin/sh -c 'test -n "$VIGIL_DEPLOYMENT_ID"'
if kubectl --context kind-vigil-phase2 -n vigil-tenant-a exec "$WORKER_A_POD" -- /bin/sh -c 'wget -qO- http://vigil-tenant-b-security:8080/healthz'; then
  echo "cross-tenant security endpoint unexpectedly reachable" >&2
  exit 1
fi
echo "basic worker identity and cross-tenant denial probes passed"
