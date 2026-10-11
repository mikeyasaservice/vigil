#!/usr/bin/env bash
set -euo pipefail

: "${LOCALSTACK_ENDPOINT:?set LOCALSTACK_ENDPOINT to the tenant-local endpoint}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
if command -v awslocal >/dev/null; then
  AWS=(awslocal)
else
  command -v aws >/dev/null || { echo "aws or awslocal is required for synthetic seed data" >&2; exit 1; }
  AWS=(aws --endpoint-url "$LOCALSTACK_ENDPOINT")
fi
"${AWS[@]}" secretsmanager create-secret --name vigil/tenant-a/jira --secret-string '{"token":"synthetic-a"}' >/dev/null
"${AWS[@]}" secretsmanager create-secret --name vigil/tenant-b/jira --secret-string '{"token":"synthetic-b"}' >/dev/null
"${AWS[@]}" s3 mb s3://vigil-tenant-a-findings >/dev/null
"${AWS[@]}" s3 mb s3://vigil-tenant-b-findings >/dev/null
echo "seeded synthetic tenant A/B secrets and object stores"
