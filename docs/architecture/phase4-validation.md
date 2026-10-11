# Phase 4 validation evidence

Date: 2026-10-11. Branch: `codex/phase4-multitenant-saas`.

This report covers the first shared-control checkpoint. It does not claim that
Phase 3 production gates passed, that shared customer data services are safe, or
that the product is ready for live multi-tenant customer data.

## Executed evidence

| Area | Result | Narrow claim |
|---|---|---|
| Python management contracts/auth/startup/workload tests | 18 passed | JWT authority claims are ignored; route tickets bind server-resolved context; OpenAPI/Postman operations and embedded manifest schema are consistent; the shared profile requires its trust material; TLS workload identity cannot come from a request header. |
| PostgreSQL shared-control tests | 3 passed | A user sees/routes only its membership; foreign workload quota use is denied; retry digest conflicts fail; concurrent reservations cannot exceed the tenant hard limit; foreign usage is not returned. |
| Complete management regression | 22 passed | The Phase 3 durable plan/approval/reconciliation lifecycle remains compatible with the Phase 4 migration and routes. |
| Pulumi Go tests and vet | Passed | Remote LocalStack endpoints and duplicate tenant IDs fail; generated IAM policy shape contains no wildcard resource; program builds and vets. |
| Postman OpenAPI lint | No issues | The self-contained OpenAPI 3.1 document passes local Postman syntax/reference validation. Enterprise governance rules were unavailable on the installed plan. |
| Management container | Built; missing-trust start refused | The non-root image contains the Phase 4 service modules and exits before binding when database/authentication trust is absent. |
| LocalStack/Pulumi apply | 18 resources created or reconciled | Explicit loopback endpoints created platform metering plus A/B KMS, versioned encrypted buckets and queues. Both tenant positive controls succeeded. |
| LocalStack direct foreign-resource probe | **Unqualified; sharing disabled** | The Community emulator allowed explicit foreign bucket reads despite different emulated account credentials. This is recorded as failed IAM evidence. No shared-data gate is marked passed and `dataPlaneSharing` remains disabled. |

The executable command is:

```bash
./infra/phase4-saas/localstack/qualify.sh managed
```

Cleanup uses `./infra/phase4-saas/localstack/qualify.sh down` and targets only
the Phase 4 Compose project.

## Limitations and next gates

LocalStack validates API interactions, Pulumi provider binding, resource shape
and deterministic A/B fixtures. It does not prove AWS IAM, KMS administration,
managed PostgreSQL role isolation, noisy-neighbor thresholds, backup extraction,
regional recovery, host isolation or customer data deletion.

The next promotion requires two actual shared-control cells under concurrent A/B
load, signed-route consumption at the edge, production mTLS deployment identity,
independent tenant recovery, bounded saturation, and AWS negative IAM tests. A
database-per-tenant shared-cluster experiment may begin only after raw-SQL role
and restore tests pass. Shared rows, workers, connector sessions, caches, vector
indexes and DSPy histories remain disabled.
