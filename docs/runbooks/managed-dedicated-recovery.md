# Managed dedicated recovery and offboarding

Status: required procedure for Phase 3 qualification. The recovery and deletion drills
described here have not run against AWS.

## Recovery authorization

Record the tenant, deployment, incident, snapshot/checkpoint, target account and region,
purpose, legal hold state, expected RPO/RTO and two-person approval. A management
operator cannot use fleet authority to read backup contents. Recovery credentials and
keys remain in the tenant data plane or designated recovery custody.

## Quarantined restore

1. Fence and cancel current mutation operations. Disable ingestion, connector effects,
   agent dispatch, model egress and customer ingress for the recovery target.
2. Create a new deployment incarnation and isolated recovery workspace. Restore the
   database and object versions into an egress-denied quarantine environment; never
   restore over the serving deployment.
3. Verify snapshot signatures/checksums, database LSN and schema, rows/objects/FKs,
   execution ledger, queue high-water mark, policy/program digests and external-effect
   journal. Record measured data and time loss.
4. Load current revocation epochs, deletion tombstones, legal holds and emergency policy
   from recovery authority outside the snapshot. Rotate human sessions, workload
   certificates, grants, signed URL keys and connector credentials. If current safety
   state cannot be verified, privileged work stays disabled.
5. Reconcile uncertain external effects individually. Never replay containment based
   only on restored queue state. Rebuild memory/search indexes with tenant credentials
   and scan for foreign or deleted canaries.
6. Run T01-T06, T10, T13-T16 controls in quarantine. A distinct approver authorizes
   cutover only after the integrity oracle passes. Keep the former deployment isolated
   until retention permits deletion.

## Failed upgrade or interrupted apply

- Preserve the operation, command, fence, plan and receipt history. Determine whether
  the provider applied no change, a known partial change or an uncertain change.
- Retry only the same approved plan and generation. A takeover uses a new command ID;
  stale reconciler callbacks are rejected.
- If the old application remains schema-compatible, restore its pinned release and run
  the T11 write-stream oracle. If rollback is incompatible, quarantine and execute an
  approved forward recovery. Do not down-migrate destructively.
- Mark service active only after checksums, acknowledged writes, ledgers, policies and
  program pins pass. Record actual RPO/RTO; engineering targets are not contractual SLA.

## Offboarding

1. Obtain customer authorization for export, retention and deletion and resolve legal
   holds. Inventory databases, objects and versions, replicas, indexes, memory, queue and
   DLQ, caches, traces, logs, program derivatives, backups and support exports.
2. Quiesce new work and reconcile in-flight effects. Revoke management, user, workload,
   connector and signed-URL authority; retain revocation/tombstone state outside backups.
3. Produce the approved encrypted export, if requested, through a tenant-bound identity.
   The management plane stores only export status and digest, never the export contents.
4. Delete with deployment-bound cleanup authority. Protected RDS, S3, KMS and state
   resources require an explicit, separately approved deletion plan; retries cannot
   broaden resource scope.
5. Verify prior credentials, URLs and restore paths fail. Record a signed receipt for
   every store and list held or immutable backups with their expiry. Do not report
   `deleted` while readable retained copies remain.

## Escalation states

- `recovery_required`: state is known enough for bounded operator reconciliation.
- `quarantined`: integrity or current revocation state is not yet proven.
- `retention_pending`: active data is deleted but an authorized hold or immutable
  backup remains.
- `customer_action_required/unverified`: customer-controlled access prevents validation.

T11 and T16 require a complete positive control, an injected failure or restoration of
old state, integrity and foreign-state checks, and signed evidence. A healthy endpoint
alone is insufficient.
