# Upgrade and rollback

Application, infrastructure, database schema, harness, policy and DSPy program versions
are independently pinned but qualified as a compatibility tuple. A release manifest
declares supported source/target schema ranges, protocol versions, migration plan,
rollback window, image/module digests, signature and required recovery checkpoint.
An approved artifact is not automatically approved for every customer deployment.

## Upgrade sequence

1. Verify target/tenant/account, release signatures, maintenance/approval policy and
   compatibility; acquire deployment lock/fencing token and compare generation.
2. Verify a recent restorable backup and key availability. Create a pre-upgrade snapshot
   where required; fail closed if the managed policy requires one and it fails.
3. Stage all artifacts and config locally. Drain or checkpoint affected executions;
   stop new incompatible work, preserve detection/enforcement capacity.
4. Apply backward-compatible schema expansion under a separate migration identity.
   Record each migration checkpoint; avoid destructive contraction in the same release.
5. Roll out application/harness; existing executions retain pinned workflow/program
   and validated envelope compatibility. Do not hand old jobs to incompatible workers.
6. Verify synthetic tenant operations, deny probes, ledger consistency, ingestion lag,
   gateway policy/approvals, error rates and customer-scoped health. Declare success
   only after the agreed observation window and durable local completion receipt.

## Rollback rules

For compatible expansion, restore previous image/config/program digests and leave
compatible expanded schema intact. For an incompatible/irreversible migration, do
not run a guessed down migration: stop the rollout, isolate writes as required and
follow an approved restore/forward-repair plan. Restoring a snapshot can lose newer
writes, so reconcile/replay the retained write and side-effect journal and measure
actual RPO. A deployment must never advertise lossless rollback where the strategy
is a point-in-time restore without replay.

Infrastructure rollback is a new reviewed plan against actual state. `helm rollback`
does not restore PostgreSQL, external secrets, object contents or cloud resources.
Never roll back key revocations, deny epochs, emergency stops, deletion tombstones or
customer support revocations with the application. Program rollback selects only a
still-approved, compatible version; policy rollback cannot loosen emergency constraints.

If management disconnects before acceptance, do not start. If it disconnects after a
fully staged operation was accepted, the local reconciler completes its preauthorized
safe checkpoint or rolls back without requesting new privilege. Expired approvals
block new privileged stages. Reconnection reconciles observed state before new commands.

The audited upstream has pre-upgrade backup and staged restore code, but
`core/backup/preupgrade.py` can skip when no destination is configured. The managed
profile must enforce its stricter backup prerequisite. T11 requires fault injection
and state-integrity evidence, not only a successful Helm render or healthy deployment.
