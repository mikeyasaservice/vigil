#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pulumi preview --stack phase2-local
