# Control plane and data plane

Decision D01: management is a separate authority, datastore, network and service
identity from customer security operations. The existing Vigil API is a **tenant
application API**, not the global control plane. Do not expose its system settings,
backup, MCP or evidence endpoints as fleet-management endpoints.

## Responsibility boundary

| Global management plane | Tenant-local data/execution plane |
|---|---|
| Organizations, tenant provisioning, region and deployment inventory | Findings, cases, events, evidence and attachments |
| Subscription, entitlements, aggregated metering | Raw usage events, workflow state and investigation ledger |
| Versioned desired configuration, feature eligibility, tenant deployment policy | Effective local policy, tenant settings, enforcement and approvals |
| Signed application/harness/DSPy release manifests | Pinned program execution, tenant evaluations and optimization |
| Health, rollout status, backup age and aggregate capacity | Detailed logs, telemetry, traces, memory, retrieval and audit |
| Support session request and approval metadata | Customer-scoped session issuance, capabilities and activity records |
| Scheduling and lifecycle reconciliation | Secrets resolution, MCP credentials, data deletion and retention |

Platform identity may update authorized desired state; it cannot mint a tenant tool
grant merely by being an operator. Product entitlements limit available features;
they do not grant permission, widen tenant policy or disable local security when a
billing/control-plane service is unavailable. Suspend automation explicitly; never
implement billing suspension as deletion of safety policy.

## Allowed flows

| Direction | Payload | Required controls |
|---|---|---|
| Plane → management | Deployment ID, revision/digest, health enum, timestamps, bucketed counts, backup status, usage quantities | Deployment mTLS binding; fixed schema, length limits, local allowlist; no arbitrary labels/log text |
| Management → plane | Signed desired revision, approved artifact digest, constrained lifecycle command | Local trust store, target binding, monotonic generation, replay journal, policy/approval validation |
| Tenant user → plane | Authorized SOC requests | Tenant membership + RBAC, local object ownership, audit |
| Worker → gateway | Signed execution grant, operation, resource reference and bounded arguments | Per-call verification; local revocation and budget reservation |
| Gateway → integration | Only approved operation with local credential | Credential scope, destination allowlist, output binding to originating execution |

No default upload of prompts, evidence, usernames, hostnames, integration URLs,
exception text, support bundles, labeled examples or optimizer traces. Even aggregate
counts can be sensitive; BYOC export policy can suppress/coarsen them. Tenant support
data exports require a separate explicit, expiring grant and a customer-visible record.

## Shared contracts (v1 design, not an implemented API)

Use versioned envelopes and reject unknown security-critical fields or versions.
These transport-independent contracts apply to all three modes. HTTP resources below
are proposed naming boundaries, not claims about upstream endpoints.

| Contract / operation | Inputs | Output and invariant |
|---|---|---|
| `DeploymentManifest` | schema version; immutable tenant/deployment IDs; mode; provider/region/account binding; generation; app, infra, schema, harness, policy and DSPy digests; approved secret/network/storage refs; budgets, retention, backup and upgrade policies | Canonical signed desired state; no secret values or arbitrary shell commands |
| `DeploymentAdapter.plan(manifest, observed)` | Verified manifest and current generation | Redacted plan digest, resource scope, risk class and required approvals; no mutation |
| `DeploymentAdapter.apply(plan, authorization, operation_id)` | Matching plan digest, expected generation, scoped authority | Durable operation ID; convergent state transitions; no cross-deployment resources |
| `observe / health` | Authenticated local instance and incarnation | Observed generation, readiness, reasons as enums, drift and backlog quantities |
| `configure / upgrade / rollback` | Desired revision, compatibility manifest, approval and recovery checkpoint refs | Audited operation state; old and new digests retained |
| `backup / recover` | Target-scoped snapshot policy or restore reference | Encrypted local snapshot and validation receipt; centrally only ID/status/age |
| `suspend / resume` | Scope, reason code, expiry, expected generation | Stop new chosen work; keep detection and safety enforcement per local policy |
| `offboard / delete` | Customer authorization, hold check, deletion plan digest | Per-store deletion receipts; retained backup expiry ledger |
| `SecretResolver.resolve(ref, execution)` | Opaque local provider reference + verified scope | Short-lived credential to connector only; no value returned to management/LLM |
| `CapabilityGateway.invoke(grant, invocation)` | Verified execution + action/resource + approval + idempotency key | Bounded result or typed refusal; audit durable before side effect |
| `Reasoner.evaluate(invocation)` | Execution ID, approved program digest, context refs, bounded inputs, budget | Typed hypothesis/action proposal, evidence refs, usage; no implicit tool authority |
| `Metering.emit(event)` | Tenant/deployment, incarnation, event ID, interval, unit, quantity, sequence | Idempotent aggregate, acknowledged sequence; no telemetry payload |

Management API resource families: `/management/v1/tenants`, `/deployments`,
`/deployments/{id}/operations`, `/releases`, `/support-sessions`. Local connector
transport: outbound HTTPS long poll initially (streaming optional); the authenticated
certificate determines its deployment, even if a URL/body contains another ID.
No central endpoint accepts arbitrary DSNs, IAM roles, bucket paths or commands from
a tenant and treats them as authorized resources.

## Command and invocation semantics

A command envelope carries `schema_version`, `command_id`, `tenant_id`,
`deployment_id`, `incarnation`, `kind`, `generation`, `expected_generation`,
`issued_at`, `expires_at`, `payload_digest`, `approval_ref`, and signer `key_id`.
Sign canonical bytes; allow only installed algorithms and locally trusted keys. mTLS
authenticates the channel, while the envelope authenticates the command across queueing.
The approval covers the exact action, target, digest and validity window. Allowed
kinds are typed lifecycle operations; no `exec`, arbitrary URL fetch or SQL payload.

At-least-once delivery is expected. Journal receipt and outcome locally; duplicate ID
and same digest return the prior outcome. Duplicate ID with changed content is a
conflict and security alert. Old generations, wrong incarnation, expiry, unknown
signer, replay and missing approval fail before mutation. An operation has states
`accepted → planning → awaiting_approval → applying → verifying → succeeded`, with
`failed`, `cancelled`, `rolling_back`, `rolled_back`, and `recovery_required` branches.
Do not claim success on acceptance. Cancellation may require reconciliation of an
already-started external side effect.

Suggested HTTP mapping: 202 + operation reference for accepted asynchronous work;
401 invalid authentication, 403 denied authority, 404 inaccessible tenant object,
409 generation/idempotency conflict, 422 incompatible manifest, 429 budget limit,
503 required authorization dependency unavailable. Error bodies contain stable code,
operation/correlation ID and retryability, never foreign resource existence or secrets.
These values become OpenAPI contracts during implementation; no management endpoints
or mock production services are introduced in Phase 1.

## Independent authorities

Release signing, fleet command signing, tenant execution signing and support-session
issuance use distinct audiences and keys. A fleet certificate cannot sign tool calls.
An artifact signature alone does not authorize installation: the local release policy
must approve that digest and compatibility set. Global management compromise can
still attempt malicious updates; BYOC requires customer approval/trusted digest policy
and bounded local reconciler permissions. See [BYOC trust](../security/byoc-trust-boundaries.md).
