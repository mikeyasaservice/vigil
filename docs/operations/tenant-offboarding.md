# Tenant offboarding and deletion

Offboarding is a recoverable, audited lifecycle operation authorized for one immutable
tenant/deployment. A subscription cancellation is not sufficient authority to delete
security evidence. Customer administrators approve the scope and export/deletion plan;
check retention, legal hold and contractual obligations before execution.

1. **Plan:** inventory every deployment/region, database, object version, attachment,
   search/vector index, memory snapshot, workflow/queue/DLQ, model cache, DSPy example,
   program derivative, trace, log, backup and support export. Record holds and responsible
   parties. Offer a scoped encrypted export before destructive steps.
2. **Quiesce:** stop new enrollment, ingestion and discretionary execution at the agreed
   time; cancel/drain active work and reconcile external effects. Record whether local
   BYOC detection remains customer-operated after management termination.
3. **Revoke:** invalidate human/service/support sessions, queued grants, workload certs,
   integration credentials, signed URLs and management trust. Persist deletion and
   revocation epochs outside restorable application snapshots. Notify integration owners
   to revoke third-party credentials we cannot revoke ourselves.
4. **Delete:** use deployment-bound cleanup identities; remove active and derived data,
   object versions/multipart remnants, replicas, indexes, queues, caches and sensitive
   local artifacts. Apply legal-hold restrictions instead of deletion where required.
   Never run an unscoped bucket/prefix/DB purge from a customer-provided resource name.
5. **Retain only authorized records:** restrict held evidence and immutable backups;
   record expiration and deletion obligations. Retain minimal commercial/audit metadata
   for the documented period; no evidence content disguised as billing metadata.
6. **Verify:** independently inventory residual resources and attempt former sessions,
   credentials, URLs and restore paths. Attach per-store receipts with resource identity,
   scope, time, method, verifier and any pending expiry. Publish a customer-visible
   completion report distinguishing deleted, held and scheduled-for-expiry data.

States: `requested → authorized → quiescing → revoked → deleting → retention_pending
→ deleted`. Each step has an idempotency key/checkpoint; retries cannot broaden scope.
Do not mark fully deleted while backups or approved holds retain readable data. Resource
IDs are never reused for a new tenant, avoiding stale grants matching a new customer.

BYOC customer chooses **detach management and retain local service** or **uninstall and
delete**. For detach, remove our access, certificates, support grants and export path;
hand over pinned artifacts/runbooks and leave local enforcement intact. For uninstall,
execute only the customer-approved local plan. If the customer has revoked management
before deletion can be verified, report `customer_action_required/unverified` rather
than claim deletion. Keys, backups and integration credentials remain under customer
control. T16/T17 validate scope, recoverability and nonresurrection of deleted authority.
