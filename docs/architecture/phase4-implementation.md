# Phase 4 shared SaaS implementation

Status: **first shared-control checkpoint implemented; shared customer data
planes and production readiness are not approved**.

Phase 4 consolidates a subsystem only after its authorization boundary and
failure behavior are executable. The first approved candidates are low-data
management functions: organization membership, tenant directory, regional-cell
routing, quota reservation and aggregate usage. Findings, evidence, prompts,
integration credentials, tenant queues, workers, capability gateways and DSPy
state remain in dedicated tenant data planes.

## Checkpoints

| Checkpoint | State | Evidence and remaining work |
|---|---|---|
| Shared identity and routing | Implemented locally | Customer JWT supplies issuer-qualified identity only. Durable membership resolves tenants and roles. A 60-second Ed25519 route ticket binds tenant, deployment, incarnation, cell, membership version and route epoch. The ticket routes to a dedicated deployment and grants no tool authority. |
| Quotas and aggregate metering | Implemented locally | mTLS SPIFFE binding selects the tenant deployment. PostgreSQL reservations are positive-only, atomic, idempotent by invocation and digest, expiry-aware and committed before accounting. Concurrent overspend and foreign-workload tests pass. |
| Regional-cell infrastructure | Development fixture implemented | Pulumi Go creates a shared metering queue and tenant-bound KMS/S3/SQS resources through explicit LocalStack endpoints. `dataPlaneSharing` is locked to `disabled-until-iam-qualified`. |
| Shared customer data services | Disabled | The LocalStack Community runtime accepted foreign explicit bucket access even with account namespaces. Shared database rows, buckets, queues, caches, search indexes and model sessions remain disallowed until actual IAM/backend negative tests pass. |
| Recovery, load and economics | Not run | Independent tenant recovery, concurrent saturation thresholds, regional evacuation, restore and measured cost-per-tenant require preproduction shared services. |

## API and state contract

- `GET /v1/saas/tenants` returns only active contexts resolved from durable
  membership. Tenant and role claims in the JWT are ignored.
- `POST /v1/saas/tenants/{tenant_id}/route` accepts a tenant selection only
  after membership and active deployment/cell checks. It returns an opaque
  signed ticket with no backend URL or credential.
- `GET /v1/saas/tenants/{tenant_id}/usage` returns tenant-scoped aggregate
  windows and never customer evidence.
- Internal quota reserve/commit endpoints require verified client TLS identity
  matching the active data-plane binding. A shared token or caller-supplied
  fingerprint cannot authenticate them.

The OpenAPI source and filesystem-local Postman collection remain in
`contracts/`. The manifest schema is embedded in OpenAPI for portable tooling
and checked against the standalone JSON schema to prevent drift.

## Cost decision

The initial consolidation removes duplicated customer-directory, route,
commercial-quota and aggregate-metering services. Their records are small,
fixed-schema metadata and do not contain SOC evidence. Pooling data-plane
databases or workers would save more fixed cost but expands T01-T06/T12-T14/T16
substantially and is not justified by current production evidence. Database per
tenant on a shared cluster is the next storage experiment after restore and
runtime-role qualification; shared rows remain last.

## Boundary record

- **Tenant boundary:** shared management tables use immutable tenant foreign
  keys and server-side membership/workload lookups. Each route still targets one
  dedicated deployment. Data-plane resource credentials are not returned by the
  shared API.
- **Identity source:** customer identity is a verified issuer/audience JWT with
  a ten-minute maximum lifetime. Tenant roles and membership version come from
  PostgreSQL. Internal usage identity comes from the verified TLS client SPIFFE
  URI and its durable deployment binding.
- **Secret/data flow:** the shared service stores organization identifiers,
  memberships, deployment/cell references, quota reservations and aggregate
  usage. Route signing material is mounted trust material. Findings, prompts,
  integration secrets and model context stay in the tenant data plane.
- **Failure behavior:** missing auth trust, signing material, membership,
  deployment state, workload binding, quota policy or database availability
  denies new work. Changed invocation content conflicts; exhausted and
  unverifiable quotas deny. A route change between lookup and issue is rechecked
  before its audit record commits.
- **Readiness tests:** this checkpoint exercises parts of T04, T05, T12 and T15.
  T01-T03/T06-T11/T13-T14/T16-T17 remain applicable to the dedicated data planes
  and to every future sharing proposal.
