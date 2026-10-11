# Backup and recovery

Each tenant has a separate backup policy, encrypted repository, retention, access
identity and key recovery plan. BYOC backups remain in the customer's account/approved
region. Central management receives snapshot identifiers, age and verification status;
it does not hold dumps, repository passphrases or unrestricted restore credentials.

## Recovery inventory

Capture PostgreSQL findings/cases/audit/execution ledger and schema version, object
evidence/attachments, tenant config and policy, workflow/agent/DSPy version bindings,
tenant program artifacts, integration secret references, necessary encrypted secret
state and key recovery material under separate custody. Include memory indexes or a
tested rebuild plan, queue checkpoints and a durable journal of external side effects.
Redis alone must not be the only record of an acknowledged investigation/action.

Define consistency across stores: record database snapshot/LSN, object version manifest,
queue high-water mark, program/policy digests and external-action journal checkpoint.
Quiesce writes when a consistent cross-store checkpoint cannot be obtained; preserve
ingestion externally or queue with a verified recovery cursor. Schema-only or memory
snapshots are not full backups. Record exclusions explicitly.

Upstream `core/backup/create.py` uses a PostgreSQL snapshot/dump and encrypted restic
repository, and `restore.py` stages a new database and verifies before swapping. Its
restore rotates JWTs and rejects pending approvals; its Bifrost request logs are excluded.
Reuse these mechanisms after qualifying them for tenant ownership, key custody,
external object/index coverage, nonresurrection of access and production recovery time.
These source observations are not successful restore-drill evidence.

## Recovery procedure

1. Authorize the specific tenant, snapshot, target and purpose; verify key access and
   signed manifest/checksums. Enforce legal holds and data residency.
2. Restore into an isolated, egress-denied environment with no active agent dispatch.
   Verify row/object counts, FKs, ledger chain, program and policy digests, secret/key
   compatibility and migration version.
3. Apply current revocations, deletion tombstones and emergency policy from an
   independently retained recovery authority. Issue a new deployment incarnation and
   rotate sessions/grants. If current safety state is unavailable, deny privileged
   actions until customer-controlled reauthorization; do not trust old backup tokens.
4. Reconcile queue/workflow state with side-effect journal. Never blindly replay an
   external action with unknown outcome. Rebuild indexes with tenant credentials and
   verify no foreign objects or stale deleted data enter retrieval.
5. Run synthetic isolation/enforcement probes, obtain cutover approval and resume in
   stages. Preserve the prior environment until integrity/retention policy permits
   deletion. Record the recovery result and measured data/time loss.

Initial **engineering targets**, not contracted guarantees: RPO ≤15 minutes for durable
security state and RTO ≤4 hours for a modest dedicated deployment. Meeting these may
require continuous WAL/object versioning in addition to periodic restic snapshots;
baseline code has not demonstrated these targets. Test restores monthly and before
major schema changes; perform regional recovery exercises at least quarterly once
offered. Document customer key unavailability and provider outage as failure scenarios.

Backups and replicas follow tenant deletion/hold policy. Where immutable backup media
cannot remove individual objects, isolate it from serving, record expiry and enforce
tombstones on every restore. Cryptographic erasure is valid only when all applicable
keys/copies are accounted for. See [offboarding](tenant-offboarding.md) and T11/T16.
