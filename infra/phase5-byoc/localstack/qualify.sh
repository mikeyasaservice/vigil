#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT="$ROOT/infra/phase5-byoc"
COMPOSE="$PROJECT/localstack/compose.yaml"
STATE="$PROJECT/.local-state"
ENDPOINT="http://127.0.0.1:4569"
DATABASE_URL="postgresql://postgres:phase5-local-only@127.0.0.1:55441/vigil_management"
ACTION="${1:-managed}"

if [[ "$ACTION" == "down" ]]; then
  docker compose -f "$COMPOSE" down -v --remove-orphans
  exit 0
fi
if [[ "$ACTION" != "managed" ]]; then
  echo "usage: $0 [managed|down]" >&2
  exit 2
fi
for command in docker pulumi go uv curl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

docker compose -f "$COMPOSE" up -d --wait
curl -fsS "$ENDPOINT/_localstack/health" >/dev/null
mkdir -p "$STATE"
export PULUMI_CONFIG_PASSPHRASE=phase5-local-only
export PULUMI_BACKEND_URL="file://$STATE"
(
  cd "$PROJECT"
  pulumi login "$PULUMI_BACKEND_URL" >/dev/null
  pulumi stack select customer-a --create >/dev/null
  pulumi config set localstackEndpoint "$ENDPOINT"
  pulumi config set accountId 111111111111
  pulumi config set tenantId tenant-a
  pulumi config set deploymentId deployment-byoc-a
  pulumi config set ownershipAcknowledgement customer-owned-account
  pulumi up --yes --non-interactive
  pulumi stack output --json > "$STATE/outputs.json"
)

UV_CACHE_DIR=/tmp/autobot-phase5-uv-cache \
UV_PROJECT_ENVIRONMENT=/tmp/autobot-phase5-venv \
uv run --with-requirements "$ROOT/requirements.lock" --with-requirements "$ROOT/services/management/requirements.txt" \
  python "$PROJECT/localstack/probe.py" --endpoint "$ENDPOINT" --outputs "$STATE/outputs.json"

PHASE3_TEST_DATABASE_URL="$DATABASE_URL" \
UV_CACHE_DIR=/tmp/autobot-phase5-uv-cache \
UV_PROJECT_ENVIRONMENT=/tmp/autobot-phase5-venv \
uv run --with-requirements "$ROOT/requirements.lock" --with-requirements "$ROOT/services/management/requirements.txt" --with pytest \
  python -m pytest -q -o addopts='' "$ROOT/tests/management/test_byoc_store_integration.py"

(cd "$PROJECT" && GOCACHE=/tmp/vigil-phase5-go-cache go test ./... && GOCACHE=/tmp/vigil-phase5-go-cache go vet ./...)
