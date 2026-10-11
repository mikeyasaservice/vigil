#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/preflight.sh
if ! kind get clusters | grep -qx vigil-phase2; then
  kind create cluster --config kind-config.yaml
fi
cilium install --context kind-vigil-phase2
cilium status --wait --context kind-vigil-phase2
echo "kind-vigil-phase2 is ready; start the isolated LocalStack instance before Pulumi up"
