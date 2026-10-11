#!/usr/bin/env bash
set -euo pipefail

kind delete cluster --name vigil-phase2
docker rm -f vigil-phase2-localstack >/dev/null 2>&1 || true
echo "removed only the named Phase 2 lab resources"
