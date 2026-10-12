# Enterprise identity and T07 validation — 2026-10-12

## Result

The enterprise identity and operator-access implementation is complete for development
qualification. Production T07 remains **PARTIAL** until the AWS and external-provider
work listed below is executed.

Implemented controls include database-backed OIDC/SAML providers, SCIM user/group
lifecycle, provider-qualified principals, MFA assurance, exact-scope JIT requests,
customer and independent provider approval, stricter break-glass approval, expiring
opaque sessions, mTLS/SPIFFE-bound per-action authorization, immediate revocation and
customer-visible hash-chained audit.

## Executed evidence

| Check | Result |
|---|---|
| Management Python suite against disposable PostgreSQL | PASS — 39 tests |
| Focused enterprise identity/operator-access suite | PASS |
| OIDC pinned-key and SAML signed-assertion/replay cases | PASS |
| OpenAPI 3.1 validation | PASS |
| Generated filesystem-local Postman collection lint | PASS — 42 requests, 0 errors, 0 warnings |
| Pulumi Go tests | PASS |
| Two-tenant LocalStack/PostgreSQL qualification | PASS |

The deployed local qualification used separate tenant A/B LocalStack endpoints,
separate support-gateway client certificates, a real PostgreSQL transaction path,
federated operator tokens, durable approvals/sessions/audit, and signed Pulumi
plan/receipt bindings. Tenant A's gateway authorized its exact health action. Tenant B's
gateway, foreign resources and five privileged actions produced denials and no foreign
inventory mutation. Customer revocation denied the next action and the customer audit
contained the allow and denial events.

## Commands

```bash
pytest -q tests/management
go test ./...
python -m openapi_spec_validator contracts/management-plane.openapi.yaml
postman collection lint /tmp/autobot-management-plane-v3.json
PHASE3_LOCALSTACK_A_PORT=4568 PHASE3_LOCALSTACK_B_PORT=4569 \
  PHASE3_MANAGEMENT_DB_PORT=55440 ./infra/phase3-aws/localstack/qualify.sh up
PHASE3_LOCALSTACK_A_PORT=4568 PHASE3_LOCALSTACK_B_PORT=4569 \
  PHASE3_MANAGEMENT_DB_PORT=55440 ./infra/phase3-aws/localstack/qualify.sh qualify
PHASE3_LOCALSTACK_A_PORT=4568 PHASE3_LOCALSTACK_B_PORT=4569 \
  PHASE3_MANAGEMENT_DB_PORT=55440 ./infra/phase3-aws/localstack/qualify.sh down
```

## Production evidence still required

- Verify the selected SAML and OIDC products, including metadata/key rotation and SCIM
  deprovision latency.
- Deploy the support gateway in AWS with production mTLS certificate enrollment and
  rotation; rerun all allow/deny/revocation cases through that workload.
- Validate audit export, retention, alerting and after-action review with a customer.
- Repeat T07 in a customer-owned BYOC account and prove customer revocation cannot be
  overridden by provider control-plane credentials.
- Exercise cloud administrator and database-owner residual authority through the
  operator threat model and monitoring controls.

LocalStack, local certificates and a shared developer host do not establish production
network, IAM, KMS, host or organizational isolation.
