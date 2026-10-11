# Migration strategy and minimum managed-service MVP

One fork follows upstream Vigil; managed-service seams are versioned additions. Reuse
domain APIs, agent ledger/projections, tool registry, deployment templates and local
backup mechanisms. Keep global management in a separate deployable; keep the same
tenant application/harness/DSPy images for all modes. Customer differences are approved
configuration and placement, never long-lived source forks.

| Phase | Deliverable and owner | Exit evidence |
|---|---|---|
| 1: baseline / architecture | Architecture+security: pinned source, table/route inventory, all-mode boundaries, threat model, test designs and decisions | Reproducible evidence, baseline test results/limitations, reviewable contracts; no live-data readiness claim |
| 2: secure execution | IAM+harness+intelligence: TenantContext/ExecutionIdentity, local authority, isolated workers, gateway, secret refs, DSPy Reasoner/registry | T02–T06/T09/T10/T12/T13 against synthetic local deployment; authorization cannot be bypassed by worker |
| 3: managed dedicated MVP | Platform+SRE: automate dedicated account/runtime/database/storage/keys, scoped management, backups/rollback, offboarding | Applicable T01–T17 on two dedicated deployments, restore/upgrade drills, customer approval/access and operating runbooks |
| 4: shared SaaS | Platform+storage+security: consolidate only approved subsystems with cost rationale | Cross-tenant tests under concurrent load on actual shared services, DB bypass proof if sharing, independent tenant recovery |
| 5: BYOC | Platform+SRE+customer: customer-account installer, outbound connector, local approvals/enforcement, customer-owned state/keys | Full customer IAM/network qualification; T08/T09/T10/T11/T15/T16/T17 in disconnected/revoked-access scenarios |

The phase numbers sequence product delivery, not when the contracts are invented.
BYOC offline/local-authority semantics and the management command envelope shape Phase 2
and Phase 3 even before customer-cloud installation is offered.

## Minimum Phase 3 scope

One supported cloud/region profile and bounded customer count; dedicated application,
agent execution nodes, PostgreSQL instance, queue/cache, object/memory stores, keys and
integration credentials per tenant. Explicit tenant/user/service identity and RBAC,
per-call gateway enforcement, pinned approved DSPy programs, resource budgets, audit,
retention, local emergency controls and safe management disconnection are mandatory.

Provide operator-driven idempotent provisioning/configuration, inventory/health, signed
release promotion, independent upgrade/rollback, verified backups/restore, scoped JIT
support, basic aggregated metering and documented offboarding. A simple internal admin
interface and manual commercial subscription reconciliation can suffice; do not build
self-service billing, marketplaces or elaborate fleet UX before the safety foundation.
Enterprise SSO/SCIM adapters have explicit interfaces; deliver the authentication and
customer access requirements of initial contracts before onboarding those customers.

Excluded initially: multi-customer worker processes, shared customer-row databases,
cross-tenant learning, arbitrary customer code/MCP installation, all-cloud support,
autonomous infrastructure upgrades and unrestricted operator shells. Features remain
disabled until their safety and operational gates pass.

## Move an existing single-instance installation

1. **Inventory and freeze baseline:** snapshot app/config/schema versions and all stores,
   integrations, secrets references, workflows, evidence/memory and active executions.
   Establish a verified backup and rollback point using synthetic restore rehearsal.
2. **Establish ownership:** register one immutable tenant and deployment for the entire
   instance after customer confirmation. Existing usernames, Azure tenant IDs and nullable
   job labels are not ownership evidence. If customer data was mixed, quarantine and
   explicitly partition it before migration; do not guess.
3. **Bind identity without merging stores:** dedicated deployment context is server-owned.
   Add membership mapping and scoped service identities. Introduce a versioned authenticated
   queue envelope and adapters for existing domain APIs; reject untrusted body tenant IDs
   in the managed profile without silently changing frozen upstream contracts.
4. **Move privileged execution behind the gateway:** parallel shadow authorization on
   synthetic traffic, then mandatory enforcement. Replace shared-token-only admission
   with execution grants; no legacy bypass remains in managed operation. Move MCP
   processes to bounded integration identities and remove backend env inheritance.
5. **Introduce DSPy incrementally:** start with one typed reasoning program, replay/evaluate
   tenant-local synthetic or authorized data, compare to baseline, approve/pin and canary.
   Retain ledger/domain adapters. Rollback selects compatible approved program/runtime.
6. **Automate dedicated provisioning:** import existing cloud resources only through a
   reviewed ownership-bound plan. Separate state, roles, network and key policies;
   backfill deployment metadata and operation receipts. Rehearse interruption/retry.
7. **Cut over:** checkpoint/drain runs, reconcile pending approvals/effects, replicate or
   restore verified data, rotate credentials/sessions and issue new incarnation. Run
   integrity and negative probes before serving live data. Keep source deployment
   read-only during the rollback window to avoid conflicting writers.
8. **Expand modes:** Phase 4 may move a tenant into a qualified regional cell without
   changing its identity or domain runtime; new deployment bindings/grants are issued.
   Phase 5 installs those same images and local authority in customer-owned resources.
   Data/region moves need customer approval and independently verified deletion of old copies.

## Upstream compatibility

Place contracts and adapters at authentication, repository, ToolDispatch, queue and
deployment boundaries. Track upstream commit plus small patch series; test upstream
API snapshots and MCP frozen schemas as well as managed contracts on every rebase.
New security envelopes need explicit protocol versions and migration compatibility.
Follow upstream contribution/license requirements for changes offered upstream. Never
quietly reinterpret legacy `tenant_id` as authenticated authority.

## Decisions to validate next

Phase 2 technical spikes: local DSPy adapter latency and provider behavior, workload
grant issuer/key rotation, container vs microVM constraints, tenant-specific network
policy and actual DB roles. Phase 3 discovery: customer target cloud/regions, data volume,
RPO/RTO/SLA, SSO needs, acceptable support policy and cost. These remain open inputs;
the dedicated-first security direction does not depend on assuming their answers.
