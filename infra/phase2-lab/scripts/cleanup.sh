#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
state_dir="${PULUMI_STATE_DIR:-${TMPDIR:-/tmp}/vigil-phase2-pulumi-state}"
if [[ -d "$state_dir" ]]; then
  pulumi login "file://$state_dir" >/dev/null
  if pulumi stack select phase2-local >/dev/null 2>&1; then
    pulumi destroy --yes --stack phase2-local
    pulumi stack rm --yes phase2-local
  fi
fi
kind delete cluster --name vigil-phase2
echo "removed only the named Phase 2 qualification resources"
