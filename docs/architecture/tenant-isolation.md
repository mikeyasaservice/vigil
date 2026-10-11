# Tenant isolation

Tenant isolation is enforced at every access path, including background and internal
paths. Possession of an object UUID, a namespace name or a tenant prompt is not an
authorization decision. Tenant A must be unable to observe, mutate, execute against,
or materially exhaust Tenant B's resources with A's application or worker credentials.
This does not promise isolation from the provider's cloud root or a compromised host;
those residual risks require separate infrastructure and operational controls.

## Isolation matrix and shared-service analysis

| Subsystem | Initial managed MVP | SaaS sharing candidate and enforcement | BYOC location | Residual risk / readiness gate |
|---|---|---|---|---|
| Edge / static UI | Shared static assets; dedicated tenant routing | Shared edge with verified audience, membership, origin and route binding; private response caching disabled | Customer ingress; UI can be locally served | Misrouting and cache poisoning; T01/T05 |
| Identity | Separate platform and tenant audiences | Shared identity broker, tenant membership grants; no email-domain auto-membership | Local verification + customer IdP | Broker compromise; T05/T07 |
| Application API | Dedicated process/runtime | Consider shared only after removing process globals and enforcing object scope everywhere | Local | Confused deputy and singleton state; T01/T02 |
| Agent / DSPy workers | Dedicated tenant VM/node capacity and hardened containers; no credential switching | Dedicated workers remain; resource admission and workload identity | Local | Kernel escape / noisy neighbor; T02/T03/T12 |
| Capability gateway | Dedicated tenant service, independently trusted from worker | Shared implementation, separate tenant deployments/keys | Local | Gateway compromise; T06/T10 |
| PostgreSQL | Dedicated instance, database, runtime roles and key | Database-per-tenant cluster first candidate; shared rows require full RLS proof | Customer instance | Cluster admin, connection pool leakage, constraints; T01/T14 |
| Queue / workflow leases | Dedicated Redis and consumer credentials | Broker ACL per tenant queue; authenticated envelope and consumer target check | Local | Wrong retry/DLQ routing and forged producer; T04 |
| Cache / model gateway | Dedicated cache store/account configuration | Tenant/deployment/policy/program-scoped keys plus access enforcement, never prefix only | Local | Reused provider sessions or cached output; T03/T04 |
| Evidence / attachments | Dedicated bucket/container and identity, per-tenant key | IAM-enforced prefixes only after negative tests; signed URLs scoped and short lived | Customer bucket | List, version, multipart or URL bypass; T01/T14 |
| Search / vector / memory | Dedicated DB/index and retriever credentials | Separate indexes/collections with backend ACL; filtered shared index last option | Local | Unfiltered ANN, facet counts, snapshots; T03 |
| MCP connectors | Dedicated process per tenant/integration credential scope | Share public immutable schemas, never authenticated sessions | Local | Process env and connector supply chain; T02/T06 |
| Secrets / encryption | Dedicated tenant store/key; per-execution scoped references | Provider service can be shared with IAM/KMS isolation | Customer secrets/key service | Host/admin decryption privileges; T02/T10 |
| Detection/config | Tenant-local mutable rules and policy | Global signed immutable rule bundles; tenant overlay authorized locally | Local | Shared mutable overlay or malicious update; T08/T13 |
| DSPy artifacts/evaluation | Public global base artifacts; tenant variants/data local | Global artifacts only if no tenant data/derivatives; explicit promotion approval | Local sensitive artifacts/evaluation | Memorized examples, tracing/export; T03/T13 |
| Audit / observability | Local tenant audit and detailed logs; central allowlisted health | Separate access partitions, bounded metric labels; export only approved fields | Local; optional metadata export | Secrets in errors/support bundles; T07/T15 |
| Backups | Dedicated encrypted repository, key and restore role | Separate repositories/access keys; no pooled unscoped dumps | Customer repository | Restore or retention resurrects access; T11/T16 |
| IaC / deployment state | Separate account role, state object/key and runner per deployment | Shared orchestration scheduler only | Customer state and local apply | Provisioning identity can escalate; T08/T17 |
| Metering / fleet metadata | Shared management DB with tenant authorization | Logical isolation, audited operator metadata access | Aggregates exported by policy | Commercial information disclosure; T04/T15 |

The matrix is a target; [the audit](vigil-phase1-audit.md) records baseline gaps.
Test IDs are defined in [production readiness](../security/production-readiness-tests.md).

## Enforcement rules

Every request gets an immutable validated TenantContext. Every queued work item
references an authenticated ExecutionIdentity; dequeue, retry, resume and dead-letter
recovery revalidate it against the consumer's deployment binding. Gateway authorization
compares grant, worker identity, resource ownership, policy version, approval, revocation
epoch and budget. Missing context denies; there is no production default tenant.

Use composite tenant/object identifiers for joins and uniqueness in any shared store.
Partition cache reads and writes, invalidation, locks, idempotency and deduplication
keys. Queues need broker permissions as well as message labels. Object storage needs
IAM as well as path prefixes. Search filters must be injected server-side, including
counts, autocomplete, export and vector retrieval; client-supplied filters cannot widen
scope. Signed URLs must identify the authorized object and expire on a bounded lease.

Tenant resource budgets cover ingestion bytes, API requests, queued work, concurrent
agents, CPU/memory/PIDs, model tokens/cost, tool calls, output bytes and stored data.
Reserve before dispatch and reconcile actual usage. Deny new discretionary work on
unverifiable/exhausted budgets; reserve capacity for ingestion, enforcement, cancellation
and audit so expensive reasoning cannot disable the security service.

Runtime manifests bind retention, region, key reference and egress policy; changes
require tenant authorization and auditable effective dates. Offboarding covers derived
memory, evaluations, backups and model caches, not just primary tables.

Kubernetes namespaces require accompanying network, identity and resource controls;
they are not sufficient on their own. NetworkPolicy allows are additive, so an
allow-all rule must be removed rather than supposedly overridden by another policy.
[Kubernetes multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/),
[network policy behavior](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
