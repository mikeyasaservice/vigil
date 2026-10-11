# Phase 3 managed dedicated MVP implementation

Status: **implementation in progress; no live-customer readiness claim**.

Phase 3 turns the Phase 2 tenant-local execution path into an operator-driven,
dedicated managed service. The first supported adapter is AWS Kubernetes. Region,
account, network and state targets are selected from trusted bindings registered in
the management plane; a manifest cannot contain provider credentials, role ARNs,
state locations, raw network IDs, Helm overrides or executable infrastructure code.

## Checkpoints

1. **Contract and durable reconciliation:** versioned DeploymentManifest, management
   OpenAPI/Postman artifacts, trusted account bindings, generation checks,
   idempotency, deployment locks, fencing and immutable operation receipts.
2. **Dedicated AWS component:** per-deployment VPC, dedicated EKS node group, RDS,
   Redis, S3, KMS and workload roles through an explicit provider and state binding.
3. **Release lifecycle:** signed compatibility tuple, plan approval, Helm install,
   enforcement-ready probes, upgrade/rollback checkpoints and safe quarantine.
4. **Recovery and offboarding:** tenant backup inventory, quarantined restore,
   current revocation/tombstone application, export/hold/delete receipts.
5. **Qualification:** two dedicated deployments run the applicable T01-T17 tests,
   including T07, T08, T09, T11, T14, T15, T16 and T17 scenarios left open by
   Phase 2.

Current checkpoint state on `codex/phase3-managed-dedicated-mvp`:

| Checkpoint | State | Evidence and remaining work |
|---|---|---|
| Contract and durable reconciliation | Implemented locally | Closed manifest/OpenAPI contracts, PostgreSQL operation/outbox/event/approval/receipt state, mTLS workload identity, signed commands, command-specific callbacks, generation fencing and real local PostgreSQL lifecycle test. AWS execution remains unqualified. |
| Dedicated AWS component | Implemented, not deployed | Explicit account-bound provider; VPC/subnets/NAT, private EKS, dedicated nodes, KMS, Multi-AZ RDS, encrypted HA Redis and private versioned S3. `go test ./...` passes. No account preview or apply has run. |
| Release lifecycle | Partial | Immutable release digests and exact Pulumi plan approval are enforced. Helm application installation, compatibility execution, rollout health oracle and rollback drill remain open. |
| Recovery and offboarding | Designed, not implemented | Procedures and failure states are documented. Backup inventory, quarantine restore, tombstone application and per-store deletion receipts still require implementation and deployed drills. |
| Qualification | Not run | T01-T17 remain release gates until two real dedicated deployments execute the required positive and negative controls. |

The current code is a reviewable infrastructure and reconciliation checkpoint. It is
not a production launch candidate and must not receive customer data.

## Initial product constraints

- One AWS region per management installation, with a bounded customer count.
- Dedicated application, execution, database, queue/cache, object store, keys and
  credentials for every tenant.
- Management stores inventory, generations, release digests, health and receipts;
  it stores no customer evidence, prompts, integration credentials or unrestricted
  data-plane connection material.
- Operator-driven onboarding and manual commercial reconciliation are acceptable.
  Shared customer workers/databases, arbitrary customer code and autonomous upgrades
  remain disabled.

## Evidence rules

Each checkpoint records the tenant boundary, authenticated identity, secret/data
flows, failure behavior and affected T test IDs. A Pulumi preview proves only plan
shape. A production gate passes only after the corresponding scenario runs against
two actual dedicated deployments with positive controls and unchanged foreign state.

## Boundary record

- **Tenant boundary:** one bound AWS account target, VPC, EKS node group, PostgreSQL
  instance, Redis replication group, evidence bucket, KMS key, Pulumi stack/backend,
  workspace and reconciler identity per deployment.
- **Identity source:** human authority comes from a configured issuer/audience JWT and
  durable server-side operator scope. Reconciler authority comes from a verified mTLS
  client certificate URI SAN matched to the trusted account binding.
- **Secret and data flow:** manifests contain opaque local references and immutable
  artifact digests. AWS role/external ID, backend, receipt key and mTLS material come
  only from a trusted local binding. The management database stores lifecycle metadata
  and receipts, not findings, prompts, connector credentials or backup contents.
- **Failure behavior:** unknown scope, target mismatch, unapproved artifact, stale
  generation, wrong command, expired lease/approval, invalid receipt, unavailable
  signer/database or provider account mismatch fails closed. Apply uses the exact saved
  and approved plan. Cancellation advances the deployment fence.
- **Readiness tests:** the implementation primarily prepares T07, T08, T11, T15,
  T16 and T17 and must rerun the Phase 2 T01-T06/T09-T14 boundaries after deployment.
