# Fleet management

One metadata control plane manages all deployment modes through the versioned
[lifecycle contract](../architecture/managed-service-lifecycle.md). The inventory stores
tenant/deployment IDs, mode, region, bound account reference, desired/observed generation,
application/harness/infra/schema/policy/DSPy digests, health timestamps, resource summaries,
backup age, maintenance window, entitlement policy and support approval metadata.
It stores no raw telemetry, prompts, credentials or unrestricted data-plane connection.

## Health and rollout

Distinguish process liveness, dependency readiness, enforcement readiness and management
connectivity. A plane with unreachable management can be locally healthy; a live pod
with unverifiable policy cannot authorize privileged work. Mark stale observations
`unknown/stale`, never healthy or suspended by inference. Suggested initial heartbeat
30 seconds, stale threshold 120 seconds; tune under measured fleet load.

Maintain release rings: internal synthetic → consenting canary → small production
cohort → wider fleet, with per-tenant windows and explicit pause criteria. Compare
ingestion lag, gateway denials, investigation completion, error rates, budget usage,
policy enforcement and backup freshness against predeclared thresholds. Do not auto-fix
security denials by widening permissions. Track managed-service policy violations as
drift, with a safe local rejection reason rather than silent overwrite.

Medic is a potential **local** health input: the audited `services/medic/README.md`
describes an off-by-default, observe-only watcher whose data stays onsite. It is not an
existing global fleet controller. Any central export needs the fixed metadata contract
and customer export policy; do not upload Medic files or arbitrary diagnostics wholesale.

## Operating loop

Reconcile desired vs observed revision with deployment locks and fencing. Bound work
per region and tenant; retry transient failures with jitter. Keep failed operations,
last safe revision and recovery status visible. Fleet queries and operator actions
are authorized by assigned tenant/customer scope even for metadata.

Meter locally using unique event IDs, incarnation and monotonic sequence. Store raw
records locally and export permitted quantities (tokens, execution seconds, storage
bytes, integration calls) by period. Dedupe late/offline retries and retain reconciliation
receipts; a missed heartbeat must not synthesize usage. Budget enforcement uses local
reservations and cannot wait for the billing pipeline. Entitlement changes never
implicitly disable local security enforcement.

Record fleet command audit centrally and administrative activity locally with correlated
IDs. Central records contain action class/status, not evidence. Keep customer-visible
audit independent of the management connection. Detailed log access follows
[operator elevation](../security/privileged-operator-access.md).

Runbooks required before onboarding: lost connectivity, certificate expiry/rotation,
revoked management access, compromised signer, failed rollout, unhealthy policy service,
full queue/audit disk, exhausted tenant budget, failed backup, lost key and regional
outage. SRE owns response; tenant administrator owns local emergency authority.
