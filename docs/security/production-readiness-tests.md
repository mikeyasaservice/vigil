# Mandatory production-readiness validation

Status: **narrow real-AWS scenarios have run, but the complete T01–T17 gates are
not passed**. Exact executed coverage and omissions are recorded in the
[2026-10-12 AWS qualification report](../architecture/aws-production-qualification-2026-10-12.md).
Do not promote a partial scenario to the full gate described below. Existing unit
tests and static architecture checks remain separate in [baseline validation](../architecture/reproducible-baseline.md).

## Test harness and gate rules

Provision synthetic A and B tenants with deliberately colliding finding, integration,
entity, cache, workflow and idempotency identifiers plus distinct canary strings.
Include an A-only user, B-only user, multi-member user, read-only user, approver, platform
operator without elevation, tenant services and adversarial workers. Use actual runtime
DB roles, gateway, broker, object store, search, model adapter and IAM bindings. Integration
and model sinks record received calls; no live customer credentials or destructive
production targets. Test API/SDK, MCP, internal, batch/export, UI backing and job paths.

Each run stores image/chart/module/program/policy/schema digests, deployment manifests,
fixture seed, test version, timestamps, sanitized requests/results, relevant audit/deny
events, sink counts and state checksums. A negative test passes only if it both denies
unauthorized effects **and** proves the legitimate control request succeeds. Timeouts,
5xx, missing fixtures, skipped tests and unavailable dependencies are not passes.

T01–T17 apply to every claimed mode. Phase 2 exercises security interfaces; Phase 3
must run isolation between two dedicated deployments, not mark it inapplicable. Phase 4
adds simultaneous adversarial load on physically shared services and privilege-bypass
tests. Phase 5 tests customer IAM, disconnection and local revocation. Phase 3 can use
the same management-protocol conformance harness for T08/T09 before a full BYOC install,
but actual BYOC qualification is still required in Phase 5. No live customer intake
until all gates applicable to the shipped surface pass; absent features remain disabled.

| ID / owner | Setup and action | Required observable result |
|---|---|---|
| T01 Data isolation / API+storage | Seed A/B findings, cases, comments, evidence, attachments. As A call B IDs through get/list/search/count/export/bulk/join/delete and object URLs; try pagination cursors and signed URL substitution | No B bytes/counts or mutation, consistent 404 for inaccessible objects; B store unchanged; A controls succeed; storage IAM denies direct reads |
| T02 Integration isolation / harness | Configure same integration name in A/B with distinct sink credentials. A invokes B reference through MCP, nested `call_integration_tool`, REST and retry/resume; compromise worker registry | Gateway denies before secret resolution; B sink receives zero calls, B credentials never enter A process/logs; A scoped invocation succeeds |
| T03 DSPy/context/memory / intelligence | Same entity keys and prompts in A/B; populate B memories/examples/cached completions. Interleave runs, model sessions, snapshots, recall, vector search, failed retries and worker reuse | No B canary in A retrieval, prompt, LM history, completion, trace, optimizer artifact or model sink; valid A recall works; no process reused across tenants |
| T04 Cache/queue / platform | Collide cache/lock/dedup/job IDs; A attempts B queue publish/read, forged jobs, retries/DLQ replay and cache invalidation; concurrent consumers | Broker/store denies foreign access; consumer rejects mismatched signed target; no B result/event/invalidations; valid duplicate delivers no extra effect |
| T05 Identity spoofing / IAM | Change tenant in header/body/path/token; use valid A token for B deployment, forged issuer/audience, expired membership, internal token as user credential | Denied before enqueue/query; stored execution context comes from membership and deployment binding; legitimate tenant switch obtains a new context |
| T06 Privileged authorization / security | Call gateway directly with no grant, shared token only, modified capabilities, wrong workload key, action/resource/argument substitution, missing approval, expired policy or unavailable verifier | Every privileged call independently denied with audited reason; zero sink effects; correctly scoped approved call succeeds |
| T07 Operator access / operations | Platform operator reads tenant data, invokes tools, downloads backup, execs a pod or changes workload role through fleet APIs. Repeat with approved narrow JIT session, then expiry/revocation | No data/tool access without elevation, exact scope honored during lease, customer-visible audit; fleet authority cannot install arbitrary data-reading code |
| T08 BYOC commands / lifecycle | Send unsigned/foreign-signed, wrong-target/account, expired, replayed, stale-generation, wrong-incarnation and unapproved commands over valid mTLS; tamper artifact digest | No resource mutation, durable rejection audit; legitimate approved command applies once; duplicate ID with changed content conflicts |
| T09 Offline enforcement / reliability | Partition only management for at least twice maximum central lease; restart connector/worker, expire management cert, fill health outbox; keep local dependencies available | Detection and locally authorized investigation continue; local deny/approval/budget policy holds; central-dependent privileges expire; bounded queue and gap signals; reconnect dedupes and rejects stale commands |
| T10 Revocation / IAM+harness | Revoke credential/capability/session during active and queued work; after local gateway acknowledgment try new dispatch, replay, resume, token renewal and restored state | Zero newly authorized effects after revocation linearization; old tokens denied despite expiry remaining; in-flight accepted effects tracked/reconciled; local epoch survives restart; central partition bound measured |
| T11 Failed upgrade / reliability | Concurrent synthetic writes; inject failures before/after app rollout, schema expansion, migration checkpoint, health check and rollback. Retry operation from another reconciler | Correct generation/fencing, no duplicate external effects, compatible old app restored or safe quarantine; tenant checksums/counts/FKs/ledger valid and committed data preserved; other tenant unaffected |
| T12 Resource isolation / platform | A saturates CPU/PIDs/memory/model tokens, queue, storage and gateway requests; crash budget store; compare B and safety capacity against agreed thresholds | A limited at admission/runtime, no overspend beyond measured in-flight reservation; B stays within predeclared SLO, detection/cancellation/audit continue; unknown budget denies new costly work |
| T13 Registry supply chain / intelligence | Try `latest`, unapproved/revoked/foreign program, tampered artifact, unsafe serialization, tenant examples in global promotion; rotate signer and rollback | Admission/load/promotion rejects before execution/export; pinned approved local program works; run resume uses original digest; rollback never restores revoked program |
| T14 Database bypass / storage | As real runtime login issue raw SQL across tenants, unset/change scope, SET ROLE/DDL/TRUNCATE, malicious search_path, joins/views/functions, concurrent pool reuse and failed transactions | Foreign reads/writes denied independent of API; runtime cannot own/alter RLS or assume bypass role; errors reveal no foreign existence; migration/backup authority separately audited |
| T15 Observability/export / operations | Embed canary secrets/evidence in tool exceptions, tags, model traces, filenames and health labels; request support bundle without export approval | Canary absent from central metrics/logs/events/bundles; fixed schema rejects free text; approved local diagnostic remains accessible only within tenant |
| T16 Recovery/deletion / storage | Backup A/B; restore A into quarantine; revoke access/delete data after snapshot; apply legal hold then offboard; attempt old URLs/credentials and restore old backup | B untouched; A restores only in authorized target with current revocations/tombstones; held data retained with restricted access; all other live/derived copies deleted and backup expiry accounted for |
| T17 Provisioning deputy / infrastructure | Substitute B account/role/state/bucket/network in A manifest; repeat failed provision, race apply, use stale fencing token and malicious pass-role request | No B mutation or credential disclosure; invalid target denied before provider call; same plan converges, state remains consistent, interrupted operation resumes safely |

## Upgrade integrity oracle (T11)

Maintain a monotonically numbered synthetic write stream, per-tenant row/object counts,
canonical content digests, FK constraints, ledger chain verification, active policy and
program digests, and a side-effect sink journal. Rollback success requires preservation
of all acknowledged writes under the tested compatibility path, not just healthy pods.
An irreversible migration must reject automatic rollback before starting; use a
quarantined recovery plan and explicitly measured RPO, never silently discard new writes.
Include mixed-version workers, duplicate queue delivery, changed config and interrupted
database migration. Restore replay must not repeat already acknowledged containment.

## Offline/revocation oracle (T09/T10)

Measure time at the gateway dispatch decision, not when the model emits a proposal.
Track grant issue/expiry, local revocation sequence and acknowledged application time.
After local revocation is durably applied, no new dispatch succeeds. During management
partition, central revocation latency is bounded by the **remaining nonrenewable lease**;
the test must expose, not conceal, that interval. Local emergency shutdown works without
management; restoring an old disk snapshot cannot reset the revocation epoch unnoticed.

Security and SRE owners sign off results per release/deployment profile. Tests must run
on PRs affecting their boundaries and in preproduction release qualification. Sharing
a new subsystem or adding an API/job/store expands the fixture surface and reruns its
negative tests. Documentation checks do not satisfy any T gate.
