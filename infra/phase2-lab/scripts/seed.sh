#!/usr/bin/env bash
set -euo pipefail

context="${KIND_CONTEXT:-kind-vigil-phase2}"
kubectl_args=(--context "$context")
if [[ -n "${KUBECONFIG:-}" ]]; then
  kubectl_args=(--kubeconfig "$KUBECONFIG")
fi

for tenant in a b; do
  namespace="vigil-tenant-$tenant"
  pod="$(kubectl "${kubectl_args[@]}" -n "$namespace" get pod -l vigil.io/qualification-target=localstack -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$pod" ]] || { echo "tenant-$tenant LocalStack pod is missing" >&2; exit 1; }
  for _ in $(seq 1 120); do
    if kubectl "${kubectl_args[@]}" -n "$namespace" exec "$pod" -- \
      curl -fsS http://127.0.0.1:4566/_localstack/health >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  kubectl "${kubectl_args[@]}" -n "$namespace" exec "$pod" -- \
    curl -fsS http://127.0.0.1:4566/_localstack/health >/dev/null
  localstack=(kubectl "${kubectl_args[@]}" -n "$namespace" exec deploy/phase2-localstack -- awslocal)
  secret="vigil/tenant-$tenant/jira"
  bucket="vigil-tenant-$tenant-findings"
  if ! "${localstack[@]}" secretsmanager describe-secret --secret-id "$secret" >/dev/null 2>&1; then
    "${localstack[@]}" secretsmanager create-secret \
      --name "$secret" --secret-string "{\"token\":\"synthetic-$tenant\"}" >/dev/null
  fi
  if ! "${localstack[@]}" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    "${localstack[@]}" s3 mb "s3://$bucket" >/dev/null
  fi
  echo "seeded tenant-$tenant LocalStack secret and object store"
done
