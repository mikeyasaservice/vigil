#!/usr/bin/env bash
set -euo pipefail

for command in docker kind kubectl helm pulumi cilium; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
docker info >/dev/null
if [[ "$(kubectl config current-context 2>/dev/null || true)" == "kind-kind" ]]; then
  echo "refusing to use the existing kind-kind context; use kind-vigil-phase2" >&2
  exit 1
fi
echo "phase2 lab prerequisites are available"
