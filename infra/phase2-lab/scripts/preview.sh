#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
state_dir="${PULUMI_STATE_DIR:-${TMPDIR:-/tmp}/vigil-phase2-pulumi-state}"
mkdir -p "$state_dir"
pulumi login "file://$state_dir" >/dev/null
pulumi preview --stack phase2-local
