# Phase 5 validation evidence

Date: 2026-10-11. Branch: `codex/phase5-byoc`.

This report covers the local BYOC checkpoint. It does not claim real AWS or
customer operational readiness, and it does not promote any T01-T17 gate based
only on LocalStack or unit tests.

## Executed evidence

| Area | Result | Narrow claim |
|---|---|---|
| Go connector/spec tests and vet | 7 passed; vet passed | Exact customer binding, immutable release pin, two-person local approval, command replay conflict, expired central lease, foreign tenant denial, sealed local state, contiguous gap markers and restart-persistent emergency revoke behave as specified. |
| PostgreSQL BYOC tests | 4 passed | Enrollment requires token, signing-key proof and the bound SPIFFE identity; signed health is contiguous/idempotent; durable central revocation blocks a fresh store process; Python and Go verify the same RFC 8785 fixtures. |
| Contract/startup tests | 9 passed | BYOC remains dedicated in the shared manifest contract, every OpenAPI operation is in Postman, unknown health data is rejected and weak enrollment authority prevents startup. |
| Complete management regression | 28 passed | Phase 3 operations and Phase 4 shared-control behavior remain compatible with the Phase 5 schema and routes. |
| Postman OpenAPI lint | No issues | The self-contained OpenAPI 3.1 document and generated filesystem collection include every BYOC operation. Enterprise governance rules were unavailable on the installed plan. |
| Management container | Built; absent trust refused startup | The non-root image includes the BYOC management modules and exits before binding when required database/authentication trust is absent. |
| LocalStack/Pulumi apply | 13 resources created | Customer-account provider created KMS, two encrypted/versioned buckets, queue and an empty secret reference using explicit loopback endpoints. Positive read/write/queue controls passed. |
| Credential-flow probe | Passed narrowly | `centralCredentialCopies=0`; Secrets Manager contains a customer-owned secret reference with no value. No claim is made about real AWS administrator access. |

The reproducible commands are:

```bash
./infra/phase5-byoc/localstack/qualify.sh managed
./infra/phase5-byoc/localstack/qualify.sh down
```

## Unqualified production gates

LocalStack does not establish AWS IAM, Organizations/SCP, VPC/private endpoint,
EKS workload identity, KMS key administration, RDS/Redis isolation or CloudTrail
behavior. The checkpoint does not issue connector certificates from CSRs, run a
continuous outbound connector daemon, deploy the Vigil runtime, restore a backup,
perform customer-controlled deletion, or execute JIT support.

Before a customer pilot, run T08/T09/T10/T11/T15/T16/T17 in a customer-owned AWS
qualification account, including a long management partition, certificate and
role revocation, release rollback, quarantined restore, offboarding receipts and
unchanged customer data after central access is removed.
