#!/usr/bin/env bash
set -euo pipefail

: "${LOCALSTACK_ENDPOINT:?set LOCALSTACK_ENDPOINT to the tenant-local endpoint}"
command -v awslocal >/dev/null || { echo "awslocal is required for synthetic seed data" >&2; exit 1; }
awslocal --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager create-secret --name vigil/tenant-a/jira --secret-string '{"token":"synthetic-a"}' >/dev/null
awslocal --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager create-secret --name vigil/tenant-b/jira --secret-string '{"token":"synthetic-b"}' >/dev/null
awslocal --endpoint-url "$LOCALSTACK_ENDPOINT" s3 mb s3://vigil-tenant-a-findings >/dev/null
awslocal --endpoint-url "$LOCALSTACK_ENDPOINT" s3 mb s3://vigil-tenant-b-findings >/dev/null
echo "seeded synthetic tenant A/B secrets and object stores"
