# Cross-tenant threat model

Scope: shared SaaS, managed dedicated and BYOC using the contracts in
[architecture](../architecture/README.md). Assets include raw/derived security data,
integration credentials, execution authority, approvals, models/programs, audit,
backups and deployment control. Adversaries include a malicious customer user,
compromised agent/MCP integration, prompt-injection author, compromised operator,
stolen service token, poisoned release and compromised shared infrastructure.

Trust boundaries: customer↔API; API↔storage; producer↔broker↔consumer;
worker↔capability gateway; gateway↔credentials/integration; data plane↔management;
operator↔tenant support; release pipeline↔customer installation; live store↔backup.

| ID | Attack and exposed asset | Enforcement / observable evidence | Residual risk | Gate |
|---|---|---|---|---|
| X01 | A substitutes B's finding/case/object ID, export filter or signed URL | Server ownership + DB role/RLS + object IAM; denied response and no bytes | Compromised privileged database/storage admin | T01/T14 |
| X02 | Client claims B's tenant ID or changes queue envelope | Server-derived immutable context, signed grant, deployment-bound consumer | Compromised identity/admission authority | T05/T04 |
| X03 | Prompt injection asks shared MCP process to run B's integration | Independent per-call gateway, tenant connector process/credential, egress deny | Malicious authorized operation within A's scope | T02/T06 |
| X04 | Shared secret lets compromised worker bypass its tool registry | Workload-bound capability and resource/policy/approval verification at gateway | Gateway takeover | T06/T10 |
| X05 | Recall same IP/hostname retrieves B's memory; optimized prompt contains B examples | Tenant retrieval store/ACL and data lineage; canary inspection across model inputs/outputs | Provider-side retention or inference leakage | T03/T13 |
| X06 | Cache key, DLQ, idempotency or dedup collision crosses tenants | Scoped keys + broker/store permissions + signed context on replay | Shared cache/broker administrator | T04 |
| X07 | Support operator uses fleet role or new pod to read evidence | Distinct audiences, JIT customer scope, bounded reconciler, customer-visible audit | Provider root can still override hosted controls | T07/T17 |
| X08 | Control-plane compromise sends code, forged command or rollback to weaken policy | Customer-approved digest policy, command signatures, nonce/generation/expiry, local veto | Customer has delegated automatic install of a malicious signed release | T08/T13 |
| X09 | Network partition suppresses revocation then stale authority acts | Local epoch/lease checks, no offline renewal of central authority, customer kill switch | Central revocation delayed until lease expiry | T09/T10 |
| X10 | SQL injection sets session tenant, assumes owner role or reads backup | Tenant login/pool and non-escalatable grants; separate migrations/backup | Cluster superuser/KMS owner | T14/T16 |
| X11 | IaC runner adopts B's resource or uses wildcard PassRole | Account/target binding, per-deployment state and runner, plan approval/fencing | Compromised scoped cloud administrator | T17 |
| X12 | Malicious program/serialized artifact executes during load | Signed reviewed code, declarative state, sandbox and lineage approval | Dependency/signer compromise | T13 |
| X13 | Noisy tenant exhausts workers, tokens, audit disk or DB | Admission reservations + CPU/memory/PID/storage quotas + safety capacity | Shared regional failures | T12 |
| X14 | Logs, support bundles, metrics or health strings export evidence | Fixed export schema, local redaction/approval, no arbitrary text fields | Inferential leakage from aggregates | T15 |
| X15 | Restore resurrects revoked tokens, approvals or deleted data | Quarantine, new incarnation, revocation checkpoint and deletion tombstones | Lost key or incomplete external side-effect journal | T11/T16 |

## Baseline risk interpretation

At the pinned Vigil baseline, the dangerous condition is placing independent customers
inside one instance whose database, MCP sessions and secrets are instance-scoped.
This audit does not claim a demonstrated exploit against a live installation. Source
paths establish missing boundaries; [readiness tests](production-readiness-tests.md)
must prove the replacement controls. Tenant labels already present in jobs do not
reduce X02 without trusted verification.

A compromised worker is in scope: it can skip its own registry and send arbitrary
gateway requests, so enforcement must live outside that worker. A host/cloud root
compromise is a documented residual risk, reduced by tenant accounts/VMs, operator
controls and key policy. Do not advertise absolute isolation from the entity able
to replace the running code and decrypt its storage.

Security owner reviews any change to an affected boundary. Release evidence includes
the attack case, artifact/config digests, denial/audit records, observed external side
effects, and residual-risk acceptance. All tenant-exposure P0s block live data; a
contractually dedicated deployment does not waive per-user or execution authorization.
