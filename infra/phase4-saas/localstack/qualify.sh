#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PHASE4_DIR="$ROOT/infra/phase4-saas"
COMPOSE_FILE="$PHASE4_DIR/localstack/compose.yaml"
STATE_DIR="$PHASE4_DIR/.local-state"
STACK_NAME="shared-cell"
ENDPOINT="http://127.0.0.1:4568"
DATABASE_URL="postgresql://postgres:phase4-local-only@127.0.0.1:55440/vigil_management"

action="${1:-managed}"
if [[ "$action" == "down" ]]; then
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
  exit 0
fi
if [[ "$action" != "managed" ]]; then
  echo "usage: $0 [managed|down]" >&2
  exit 2
fi

for command in docker pulumi go uv; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

docker compose -f "$COMPOSE_FILE" up -d --wait
curl -fsS "$ENDPOINT/_localstack/health" >/dev/null

mkdir -p "$STATE_DIR"
export PULUMI_CONFIG_PASSPHRASE="phase4-local-only"
export PULUMI_BACKEND_URL="file://$STATE_DIR"
(
  cd "$PHASE4_DIR"
  pulumi login "$PULUMI_BACKEND_URL" >/dev/null
  pulumi stack select "$STACK_NAME" --create >/dev/null
  pulumi config set localstackEndpoint "$ENDPOINT"
  pulumi config set --path 'tenantIds[0]' tenant-a
  pulumi config set --path 'tenantIds[1]' tenant-b
  pulumi up --yes --non-interactive
  pulumi stack output --json > "$STATE_DIR/outputs.json"
)

UV_CACHE_DIR="/tmp/autobot-phase4-uv-cache" \
UV_PROJECT_ENVIRONMENT="/tmp/autobot-phase4-venv" \
uv run --with-requirements "$ROOT/requirements.lock" --with-requirements "$ROOT/services/management/requirements.txt" \
  python "$PHASE4_DIR/localstack/probe.py" --endpoint "$ENDPOINT" --outputs "$STATE_DIR/outputs.json"

PHASE3_TEST_DATABASE_URL="$DATABASE_URL" \
UV_CACHE_DIR="/tmp/autobot-phase4-uv-cache" \
UV_PROJECT_ENVIRONMENT="/tmp/autobot-phase4-venv" \
uv run --with-requirements "$ROOT/requirements.lock" --with-requirements "$ROOT/services/management/requirements.txt" --with pytest \
  python -m pytest -q -o addopts='' "$ROOT/tests/management/test_saas_store_integration.py"
