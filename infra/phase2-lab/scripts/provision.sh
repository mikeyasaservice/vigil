#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/preflight.sh
if ! kind get clusters | grep -qx vigil-phase2; then
  kind create cluster --config kind-config.yaml
fi
if ! cilium status --context kind-vigil-phase2 >/dev/null 2>&1; then
  cilium install --context kind-vigil-phase2
fi
cilium status --wait --context kind-vigil-phase2
echo "kind-vigil-phase2 is ready; Pulumi will create tenant-local qualification targets"
