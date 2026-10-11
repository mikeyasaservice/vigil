# Vigil Phase 1 managed-service architecture audit

Audited fork: `https://github.com/mikeyasaservice/vigil` at
`0226200c476913b8bd5dff1df9bb221c6b147186`, retrieved 2026-10-11.
The workspace initially contained no code or prior audit. An independent checkout of
the user-specified fork was established here; unrelated parent-repository changes were
not modified. No cloud deployment or customer-data access was performed.

**Conclusion:** this baseline has useful single-instance authentication, agent and
deployment mechanisms, but does not implement true organization-level multi-tenancy.
Do not combine independent customers in one instance or accept live managed-service
customer data before the [release gates](../security/production-readiness-tests.md).
Adopt dedicated tenant data/execution planes first, with common management contracts.

## Method and limits

Inspected schema snapshot and SQL initialization, identity/middleware, findings/cases,
agent queue/ledger/tool routes, MCP credential/session handling, memory/recall, singleton
configuration, Docker/Helm, backup/restore and Medic. Generated a reproducible table and
route declaration inventory without importing the application. Ran agent type-check
and unit tests plus Helm rendering experiments; see [baseline](reproducible-baseline.md).

Verified = direct evidence for the narrow stated claim, not blanket security approval.
Partial = mechanisms exist but full requirement is unmet. Unsupported = inspected
architecture lacks the required mechanism. Unknown = not enough source/runtime evidence.
This is a source architecture audit, not an exhaustive vulnerability scan or exploit
demonstration. Live DB grants, CNI enforcement, installed cloud IAM, external indexes,
actual restore behavior and every dynamically mounted endpoint remain unverified.

## Evidence register

Links pin the audited commit rather than mutable `main`.

| ID | Evidence and observation |
|---|---|
| E01 | [Schema snapshot](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/schema.snapshot.json), [generated tables](evidence/tables.csv): 55 tables; zero tenant/organization key columns |
| E02 | [User/role models](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/models/auth.py#L24): user has one role reference; no organization membership model in inspected schema; MCP credential belongs to a user |
| E03 | [Start run](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/api/v1/agent_runs_router.py#L52): optional body `tenant_id` is passed into queue at line 169; listing at line 100 lacks tenant context |
| E04 | [Job contract](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/agent/contracts/job.ts#L10): one `agent-runs` queue, nullable tenant label; [worker](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/agent/worker.ts#L549) constructs a null-tenant resume job |
| E05 | [Findings storage](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/service.py#L311) retrieves by finding ID; [case repository](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/case_repository.py#L345) retrieves by case ID; no tenant scope in these signatures |
| E06 | [Internal auth](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/agents/internal_auth.py): `AGENT_INTERNAL_TOKEN`, constant-time comparison, absent config→503, invalid token→401 |
| E07 | [Tool invoke](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/agents/tools_router.py#L200): shared-token check, optional signed person principal; no required tenant/execution grant. [Principal token](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/auth/tool_principal.py) signs username/audience/expiry |
| E08 | [Registry](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/agent/core/registry.ts): deny-by-default tool grants per workflow role; [approval tool](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/agents/tool_registry.py#L480) requires bound person/right to approve |
| E09 | [MCP service env](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/integrations/mcp/service.py#L282) copies backend environment; [MCP client](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/integrations/mcp/client.py#L285) passes `server.env`; client sessions/caches keyed by server name; process client singleton at line 705 |
| E10 | [Secrets manager](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/secrets_manager.py#L318): encrypted file/master key in instance state, environment synchronization, singleton at line 797; [integration naming](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/integrations/integration_secrets.py#L46) maps integration/field to env key, not tenant/execution |
| E11 | [Recall SQL](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/memory/recall.py#L113) selects entity keys/time; [ledger reads](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/agent/ledger/repository.ts#L29) scoped by run ID only |
| E12 | [DB singleton](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/connection.py#L464), [cached settings](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/config.py#L369), [runtime config cache](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/platform/runtime_config.py#L44), [ARQ queue](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/llm/gateway/gateway.py#L21) are instance/process scoped |
| E13 | [App role SQL](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/infra/database/init/30_vigil_app_role.sql): `NOSUPERUSER`, broad table DML/schema CREATE, agent-event mutation revocation; no tenant RLS policies found in initialization SQL |
| E14 | [Network policies](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/infra/helm/vigil/templates/networkpolicy.yaml): allow-all egress, broad namespace ingress options; [values](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/infra/helm/vigil/values.yaml#L868) disables policies by default |
| E15 | [Compose](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/infra/docker/docker-compose.yml): hardcoded `deeptempo-*` names/host ports and instance volumes; [Helm chart](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/infra/helm/vigil/Chart.yaml) and values expose external DB/Redis and secret references |
| E16 | [Backup create](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/backup/create.py), [restore](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/backup/restore.py), [pre-upgrade](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/backup/preupgrade.py): reusable local mechanisms; missing destination can skip backup; fleet/PITR guarantees untested |
| E17 | [Auth route tests](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/tests/security/test_route_auth_coverage.py), [current-user resolver](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/auth/current_user.py): instance auth/DEV_MODE behavior; not tenant authorization evidence |
| E18 | [Medic](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/medic/README.md): local observe-only health watcher, off by default; [INTENT.md](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/INTENT.md) declares observe-only policy comparison, not enforcement |
| E19 | [Rate limiter](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/api/middleware/rate_limit.py) keys on remote address and falls back in-memory; [S3 service](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/core/storage/s3_service.py) takes bucket/key without a tenant context |
| E20 | [Agent package](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/services/agent/package.json) and [Python dependencies](https://github.com/mikeyasaservice/vigil/blob/0226200c476913b8bd5dff1df9bb221c6b147186/requirements.txt): no DSPy integration found in audited runtime/dependency search |

## Required audit answers

| # | Question | Classification and answer |
|---|---|---|
| 1 | True organization multi-tenancy? | **Unsupported.** Instance roles/users do not establish organizations, membership or tenant data isolation (E01–E05) |
| 2 | Which tables/APIs lack tenant enforcement? | **Unsupported** on reviewed paths. All 55 snapshot tables lack tenant columns; findings/cases/run APIs and internal tools use instance stores. Full [table](evidence/tables.csv) and [route worklist](evidence/routes.csv) supplied; reviewed API families below (E01/E03/E05/E07) |
| 3 | Caches, queues, indexes, jobs assuming one context? | **Partially supported** as instance-local services; tenant partitioning **unsupported**. BullMQ `agent-runs`, ARQ `arq:llm`, runtime config, MCP caches, memory SQL and distil/ledger state have no enforced tenant context. External search/model cache isolation **unknown** (E04/E09/E11/E12) |
| 4 | How does agent authenticate? | **Verified (source)**: deployment shared internal bearer; optional signed person attribution on tool calls. Execution-specific tenant authentication **unsupported** (E06/E07) |
| 5 | Permissions bound to customer, user or global config? | **Partially supported**: role/tool grants and selected user-bound approval checks exist; most runtime config/integration authority is instance-wide, not tenant/execution-bound (E07–E10) |
| 6 | Can shared MCP access another tenant integration? | **Unsupported isolation**: no tenant distinction in server-name session/config/credential lookup. If customers share the process/store, their integrations are not separated by these paths. Exploit not run (E09/E10) |
| 7 | Credentials per tenant/execution? | **Partially supported** for physically separate instance stores; per-execution short-lived credential isolation **unsupported** in inspected store/API (E10) |
| 8 | Singleton/global blockers? | **Verified (source)**: DatabaseManager, settings LRU, runtime config cache, secret manager, process MCP client, provider registry, shared ARQ gateway. They require dedicated processes or explicit contextual adapters (E09/E10/E12) |
| 9 | Multiple isolated Vigil instances? | **Partially supported**: separate infrastructure can host copies. Helm release/namespace parameterization helps; Compose fixed names/ports collide. No concurrent installed-instance test, workload IAM/keys/restore independence unverified (E15) |
| 10 | Helm/Docker automated provisioning? | **Partially supported**: chart templates, probes, external services and locks are reusable. Default chart render failed under installed Helm due to `.helmignore`; corrected temporary copy renders. No managed reconciler/idempotency/recovery proof (baseline/E14/E15) |
| 11 | Central vs local capabilities? | **Unsupported as a split management platform**; selected target boundary is [control/data planes](control-plane-data-plane.md). Existing tenant API/Medic are reusable locally, not evidence of global fleet management (E18) |
| 12 | Can DSPy operate locally? | Existing integration **unsupported** (E20); feasibility **partially supported by architecture** because local Python reasoning adapter can be introduced. Performance/provider compatibility **unknown** until Phase 2 spike |
| 13 | Safe disconnected operation? | **Unknown** as a managed/BYOC guarantee: baseline is local and has no designed management dependency, but that does not prove offline grant, policy, revocation, upgrade or outbox semantics. INTENT observe mode is not local policy enforcement (E18) |
| 14 | Material exposure code paths? | **Verified missing boundaries in source**, not runtime exploit: body tenant propagation, unscoped object/ledger/recall queries, token-only tool dispatch, process MCP/env/secrets and permissive deployment network defaults (E03–E14) |
| 15 | Required before live data? | **Unsupported production readiness**: Phase 2 trusted identity/gateway/isolation, Phase 3 dedicated provisioning and operator/backup controls; applicable T01–T17 must pass. No existing user/workspace feature waives these gates |

## Table and API coverage

Every table in [tables.csv](evidence/tables.csv) needs explicit ownership classification
before sharing. The inspected schema groups are:

| Group | Tables | Required boundary |
|---|---|---|
| Identity/config | `users`, `roles`, `mcp_credentials`, `user_preferences`, `system_config`, `integration_configs`, `federation_sources`, `config_audit_log`, `sketch_mappings` | Tenant membership and tenant settings/credential scope; platform identity stored separately |
| Findings/intel | `findings`, `finding_mitre_predictions`, `shared_iocs`, `threat_indicators`, `ip_exclusions` | Tenant scope even where a table says shared; only explicitly public reference feeds may be globally shared |
| Cases | `cases`, `case_findings`, `case_attachments`, `case_audit_logs`, `case_closure_info`, `case_comments`, `case_escalations`, `case_evidence`, `case_iocs`, `case_metrics`, `case_notifications`, `case_relationships`, `case_slas`, `case_tasks`, `case_templates`, `case_watchers`, `sla_policies` | Tenant root and composite parent/child relationships |
| Execution | `agent_events`, `agent_directives`, `agent_run_leases`, `approval_actions`, `custom_agents`, `custom_workflows`, `workflow_runs`, `workflow_run_phases`, `investigations`, `investigation_logs`, `intake_triggers` | Tenant/deployment/execution binding on writes, reads, resume, cancellation and retention |
| Memory | `episodic_sightings`, `episodic_verdicts`, `episodic_verdict_sources`, `episodic_gaps`, `episodic_distil_markers`, `episodic_distil_failures`, `episodic_read_log` | Tenant-scoped retrieval, snapshots and distillation |
| Intelligence/chat | `ai_decision_logs`, `ai_model_configs`, `llm_interaction_logs`, `llm_provider_configs`, `conversations`, `chat_messages` | Tenant prompts, credentials, logs and model context |

Reviewed API families needing tenant-aware enforcement: `core/api/v1/findings_router.py`
(list/get/summary/update), `cases_router.py` (case operations), `agent_runs_router.py`
(start/list/detail), `services/api/routers/findings.py` (bulk enrichment, clear and
export), `core/agents/tools_router.py` (backend/MCP invocation), case search services,
and MCP wrappers in `tools/mcp/vigil.py`. Authentication and permission gates exist;
the missing property is customer-scoped object/resource ownership, not necessarily
unauthenticated access. All remaining declarations in routes.csv are review work, not
individually certified safe or confirmed vulnerable.

Background inventory: daemon federation polling reads instance integration config;
ARQ and BullMQ share their configured broker namespace; worker resume constructs null
tenant context; episodic distil jobs/read logs and snapshots share one database; backend
MCP processes inherit instance configuration; backup/retention sweep the instance.
Case full-text search and episodic GIN indexes inherit the same database scope. The
actual deployment of external OpenSearch/S3/provider caches is **unknown**, so require
tenant-bound adapter credentials and negative tests rather than assume safety.

## Prioritized changes

| Finding | Severity for managed multi-customer use | Required change / phase / gate |
|---|---|---|
| F01 No organization ownership/membership enforcement | P0 | Server TenantContext + explicit deployment ownership + data access boundaries; Phase 2; T01/T05/T14 |
| F02 Client-supplied/null tenant queue labels and run-ID-only ledger | P0 | Signed execution identity, versioned queue envelope, scoped consumers/resume; Phase 2; T04/T05/T10 |
| F03 Internal bearer is not tenant capability authorization | P0 | Independent gateway verifies every privileged action; Phase 2; T02/T06 |
| F04 MCP/secrets/env/client sessions are instance-global | P0 | Dedicated tenant processes + narrow connector secret leases and egress; Phase 2; T02/T03/T12 |
| F05 Memory/model/config state not tenant partitioned | P0 | Local scoped retrieval, DSPy registry/lineage and model cache isolation; Phase 2; T03/T13 |
| F06 Network policies off/permissive; shared runtime roles | P0 for production boundary | Managed overlay with enforced deny egress, precise peers, role separation and provider IAM; Phase 3; T06/T14/T17 |
| F07 Operator/management/customer trust split absent | P0 before managed service | JIT scoped access, local signed-command validation, export contract and audit; Phase 3; T07/T08/T15 |
| F08 Offline/revocation semantics not established | P0 before management-dependent operation | Local authority, durable deny epochs, bounded central leases/outbox; Phase 2/3 and BYOC Phase 5; T09/T10 |
| F09 Upgrade/restore/deletion guarantees unqualified | P0 before live data | Mandatory backups, restore integrity, independent upgrade/rollback and deletion receipts; Phase 3; T11/T16 |
| F10 Helm archive-ignore render failure; Compose collisions | P1 delivery blocker | Qualify supported Helm toolchain, fix packaging, automate tenant manifests; Phase 3; T17 |

Preserve useful upstream controls and add small adapters near its existing domain,
ToolDispatch, queue and ledger seams. Avoid rewriting the SOC or implementing all three
modes in Phase 1. [Migration plan](migration-strategy.md).
