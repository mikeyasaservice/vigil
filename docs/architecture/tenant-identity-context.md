# Tenant identity and execution context

## Three identity scopes

| Scope | Issuer and authority | Prohibited inference |
|---|---|---|
| Platform | Provider workforce SSO/workload issuer; metadata/fleet grants | Platform administrator does not become a tenant analyst or tool operator |
| Tenant | Customer IdP/local service issuer + server-side membership | A login, role name, domain, tenant header or selected organization is not membership |
| Execution | Tenant-local trusted admission authority; immutable signed claims | A model, worker payload or configuration file cannot assign its own privileges |

Membership is `(subject_id, tenant_id, role_set, membership_version, status)`; subjects
use issuer + immutable subject, not mutable email/username. Roles include tenant admin,
analyst, approver and read-only viewer. Service identities receive independent grants.
SAML/OIDC federation maps into this model; SCIM manages membership lifecycle and revokes
sessions. Optional ABAC adds resource sensitivity, time, device or region constraints;
it cannot bypass tenant membership. Re-check membership on tenant switch and privileged
actions; role changes revoke existing authority and queued work requiring it.

## Request context

1. Validate credential signature, issuer, audience, expiry and revocation using trusted
   configuration. Separate platform, tenant and execution audiences and signing keys.
2. Resolve requested tenant against active membership; lookup the approved deployment
   binding server-side. A body/header may select a tenant only as an untrusted hint.
3. Construct immutable `TenantContext{tenant_id, deployment_id, subject_id,
   subject_kind, roles, membership_version, policy_version, request_id}`.
4. Pass it explicitly into repositories/services; bind DB role, index and secret
   resolver using a trusted binding registry. Never form these from user strings.
5. Enforce object ownership and operation permission at the storage/service boundary,
   including internal tools and background tasks; record decisions locally.

Dedicated installations still construct and validate this context against their one
registered tenant. There is no special auth bypass for single-tenant mode. Reject
conflicting path/header/body/token identities. A legitimately multi-tenant user gets
a newly validated context for each request; a running execution cannot switch tenants.

## ExecutionIdentity v1

| Required claim | Meaning |
|---|---|
| `schema_version`, `issuer`, `audience`, `key_id` | Contract and explicit verification trust |
| `tenant_id`, `deployment_id`, `incarnation` | Immutable ownership and current installation lineage |
| `agent_id`, `agent_release_digest` | Approved agent definition/runtime |
| `workflow_id`, `workflow_version`, `workflow_digest` | Immutable workflow definition |
| `execution_id`, `parent_execution_id` (nullable) | Unique execution and delegated lineage |
| `initiator_subject`, `initiator_kind`, `membership_version` | Human/service trigger with durable authorization basis |
| `program_id`, `program_version`, `program_digest` | Approved pinned DSPy selection |
| `capabilities` | Action + resource scope + integration reference + limits, no wildcards by default |
| `policy_version`, `policy_digest`, `revocation_epoch` | Effective locally verifiable policy and freshness |
| `approval_context` | Explicit `not_required` with policy basis OR approval IDs/digests/expiry; never missing by implication |
| `budget_ref`, `issued_at`, `not_before`, `expires_at`, `jti` | Reserved budget and bounded authorization lifetime |
| `confirmation` | Binding to the admitted worker/workload key, preventing simple bearer transfer |

The authority signs the identity at admission; it stores an immutable digest with the
workflow and queue reference. Application schemas and runtime immutability prevent
accidental mutation; signatures, workload binding and trusted verification enforce the
security property across processes. An execution can receive a narrower replacement
grant; widening requires new authorization and explicit audit, not editing old claims.

Tool grants are narrower, audience-specific, short-lived derivatives (initial target:
60 seconds maximum) with execution ID, action/resource, argument constraints, policy,
approval digest, nonce and workload binding. Exact lease values are security policy,
not a customer SLA. Local revocation is checked on **every** privileged dispatch; a
still-unexpired token is insufficient. Approval for a destructive operation binds its
normalized arguments and resource, and cannot be reused for different actions.

Queue payloads contain grant references/digests and bounded request references, not
credentials. Authenticated producers and broker ACLs restrict publication. Consumers
verify the grant, target and current policy before resuming, and use fresh short-lived
tool grants. Replay creates no extra external effects: reserve an invocation ID with
the normalized argument digest; uncertain results require reconciliation.

## Disconnection and revocation

The tenant-local authority and gateway do not need global connectivity to verify local
policy, workload identity or customer approvals. Locally authorized detection and
investigation continue. Privileged actions dependent on central/support authorization
stop when their lease/freshness expires; no fallback to a global shared token.

A central revocation cannot arrive during a network partition. Record this limitation:
central sessions are bounded by their local lease, while local customer revocation and
emergency stop take immediate effect at the next dispatch. Never renew a central lease
offline. Actions authorized entirely by local standing policy can receive local grants
while disconnected. If the local revocation/policy store is unavailable, fail closed for
privileged actions and keep passive ingestion/detection within independently valid policy.
See [BYOC failure behavior](byoc-reference-architecture.md).
