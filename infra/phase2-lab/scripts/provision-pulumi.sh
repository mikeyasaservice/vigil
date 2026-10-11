#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pulumi up --yes --stack phase2-local
