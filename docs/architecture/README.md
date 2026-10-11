# Managed autonomous SOC: Phase 1 architecture

Status: **architectural direction selected; source-audited; production isolation unverified**.
Baseline date: 2026-10-11. Fork: `https://github.com/mikeyasaservice/vigil`.
Commit: `0226200c476913b8bd5dff1df9bb221c6b147186`.

Vigil is presently an instance-scoped SOC, not a verified organization-multi-tenant
platform. A nullable job tenant label does not provide isolation. Do not accept live
customer data until the applicable [readiness gates](../security/production-readiness-tests.md)
pass on the actual deployment. This is a Phase 1 design and baseline, not a claim that
the control plane, DSPy runtime, secure harness, or BYOC connector has been implemented.

## Decisions

| ID | Decision | Why / reconsideration trigger |
|---|---|---|
| D01 | One global metadata management plane; tenant-local data and execution planes | Management must not imply unrestricted evidence access |
| D02 | Dedicated application, workers, PostgreSQL instance, queue/cache, credentials and keys for the initial managed MVP | Existing process singletons and unscoped data paths; reconsider sharing only after isolation tests and measured savings |
| D03 | Authenticated tenant/deployment context and separate execution grants | Human, operator and workload authority must not be interchangeable |
| D04 | A local trusted capability gateway is the only privileged agent tool route | Reasoning and prompts cannot enforce authorization |
| D05 | DSPy runs inside each data plane with approved, pinned artifacts | Sensitive optimization examples and invocation context stay local |
| D06 | Outbound mutually authenticated BYOC management; locally constrained signed commands | Customer can revoke management without disabling local enforcement |
| D07 | Versioned DeploymentManifest + reconciler adapter; Pulumi Go infrastructure, Helm application releases | Reuse the chart while isolating provider-specific provisioning |
| D08 | Add shared services incrementally in Phase 4 | Dedicated execution workers remain required; shared rows are not the default |
| D09 | Immutable artifact digests and independent app/infrastructure/policy/program revisions | Support tenant-specific promotion, compatibility checks and recovery |

These decisions are design choices for this fork. They are not upstream guarantees or
customer contractual commitments. Initial AWS reference selection is provisional:
customer demand has not yet been supplied.

## Read in this order

1. [Source audit and answers to all 15 audit questions](vigil-phase1-audit.md),
   [reproducible baseline](reproducible-baseline.md), and [evidence inventory](evidence/README.md).
2. [Deployment models and three diagrams](deployment-models.md),
   [control/data planes and contracts](control-plane-data-plane.md).
3. [Isolation matrix](tenant-isolation.md), [identity context](tenant-identity-context.md),
   [database strategy](multi-tenant-database.md), [execution isolation](agent-execution-isolation.md).
4. [DSPy registry](dspy-program-registry.md), [BYOC reference](byoc-reference-architecture.md),
   [deployment lifecycle](managed-service-lifecycle.md), [cost and complexity](cost-and-complexity.md).
5. [Cross-tenant threat model](../security/cross-tenant-threat-model.md),
   [operator access](../security/privileged-operator-access.md),
   [BYOC trust](../security/byoc-trust-boundaries.md), [mandatory tests](../security/production-readiness-tests.md).
6. [Fleet](../operations/fleet-management.md), [upgrades](../operations/upgrade-and-rollback.md),
   [recovery](../operations/backup-and-recovery.md), [offboarding](../operations/tenant-offboarding.md),
   [migration and phased delivery](migration-strategy.md).
7. [Phase 2 implementation and validation](phase2-validation.md).
8. [Phase 3 managed dedicated implementation](phase3-implementation.md) and
   [current Phase 3 validation evidence](phase3-validation.md).
9. [Phase 4 shared SaaS implementation](phase4-implementation.md) and
   [current Phase 4 validation evidence](phase4-validation.md).
10. [Phase 5 BYOC implementation](phase5-implementation.md) and
    [current Phase 5 validation evidence](phase5-validation.md).

## Validation meaning

**Verified** means the specific, narrow claim has direct source or test evidence;
**partially supported** means useful mechanisms exist but do not meet the full
requirement; **unsupported** means inspected architecture lacks a required mechanism;
**unknown** means evidence is insufficient. Every runtime isolation test remains
NOT RUN until executed with adversarial tenant fixtures against the deployed system.

Phase 1 validates the direction through pinned source evidence, subsystem inventory,
contract consistency, threat/failure walkthroughs, baseline checks and explicit exit
gates. It does not substitute for penetration testing or operational qualification.
Architectural changes must update the affected contract, threat and readiness test
together; tenant isolation is a release condition, not a later feature.
