# AWS production qualification — 2026-10-12

Status: **two real dedicated development environments qualified narrowly; full
production and customer-owned BYOC gates remain open**.

This run used synthetic tenant data in the authorized AWS development account.
It did not use customer telemetry. Tenant A and B had separate VPCs, EKS
clusters, Aurora clusters, Valkey Serverless caches, KMS keys, Secrets Manager
records, S3 buckets, queues, credentials and dedicated agent/reasoner/connector
pods. A same-account BYOC resource fixture was also exercised and is labeled as
development qualification rather than customer-owned evidence.

## Deployed versions and shape

| Component | Qualified value |
|---|---|
| EKS | Kubernetes 1.36, platform `eks.14` |
| Worker compute | two `m7g.large` ARM64/Graviton nodes per tenant |
| Database | Aurora PostgreSQL 16.9, Serverless v2, 0–8 ACU, two instances per tenant, 300-second auto-pause |
| Cache | Valkey Serverless, dedicated per tenant |
| Helm | chart/app 0.7.0; revision 4 in both current isolation environments |
| Backend image | `qual-20261012-isolation-r2` |
| Agent image | `qual-20261012-isolation-r1` |
| Connector image | `qual-20261012-isolation-r3` |
| Reasoner image | `qual-20261012-isolation-r2` |
| Tooling | Pulumi 3.244.0, Helm 4.3.0, kubectl 1.37.0, AWS CLI 2.34.37, Go 1.27.1 |

The current isolation run used source commit `a2ada82` plus the queue-state
qualification correction committed with this report. Raw evidence remains in the mode-0700 local qualification
roots under `/tmp/vigil-aws-qualification` and
`/tmp/autobot-byoc-qualification`; those paths contain account-specific resource
identifiers and are intentionally not committed.

## Executed evidence

| Evidence | Result | Exact narrow claim |
|---|---|---|
| Isolation matrix `20261012T143212Z` | Passed, 44/44 assertions | Two live dedicated environments passed same-tenant positive controls; colliding finding/case/evidence/comment/attachment/IOC/search/export and S3 isolation; tenant-local episodic recall; pinned DSPy managed execution; issuer/audience/expiry/membership/session denials; exact grant-substitution denials; direct database and peer-broker bypass denials; idempotent exact queue redelivery; altered-envelope failed-queue placement; zero replay connector effects; and foreign observability-canary absence. |
| Runtime `20261012T015858Z` | Passed | Distinct colliding findings; A and B each completed a pinned DSPy managed investigation; foreign token and tenant-header substitution denied. |
| Boundaries `20261012T015921Z` | Passed | Workload identities read only their own secret; deployment roles could not read the other secret; own DB/cache positive controls connected while foreign private endpoints resolved but did not connect; worker direct backend/connector paths and worker-token-only legacy invocation were denied. |
| Lifecycle `20261012T020024Z` | Passed | Exact two-person approval binding; altered approval rejected; durable cancellation survived security-service restart; interrupted execution resumed with the original program digest; revoked program tombstone could not be deleted or reactivated. |
| Recovery `20261012T020527Z` | Passed | An Aurora snapshot restored into a private quarantine cluster with identical finding canary, table counts, run digest and ledger digest; the temporary restore was removed. A versioned KMS S3 object was deleted by exact version and became unreadable. |
| Rollback `20261012T022826Z` | Passed | A nonexistent agent image caused Helm revision 6 to fail; atomic rollback produced revision 7 with the exact previous image; both A and B completed managed investigations afterward. This did not exercise schema-migration rollback. |
| Load `20261012T024345Z` | Passed | During 48 concurrent A admissions, all 50 B reads succeeded with 0.637-second p95 against a declared 2-second threshold, and B completed an investigation in 2.49 seconds against a 180-second threshold. |
| BYOC AWS `20261012T024229Z` | Passed narrowly | In the same development account, KMS rotation, S3 KMS encryption/versioning, SQS KMS binding, an empty secret reference and an exact versioned object worked. This is not customer-owned-account evidence. |
| BYOC offboarding `byoc-offboard.json` | Passed narrowly | Direct AWS queries confirmed both S3 buckets and the SQS queue were gone, and the integration secret and KMS key were gone or in AWS scheduled-deletion state. This remains same-account development evidence. |
| Historical dedicated offboarding `offboard-a.json`, `offboard-b.json` | Passed | Pulumi deleted 92 resources per tenant in the earlier drill. Direct queries confirmed EKS, Aurora, manual Aurora snapshots, Valkey, VPC, S3, runtime secret, KMS key, six ECR repositories and the workload IAM role were deleted or in the documented AWS scheduled-deletion state. The current isolation environments are a later deployment and remain active. |
| Historical qualification authority offboarding `offboard-bootstrap.json` | Passed | Pulumi deleted the earlier 10-resource bootstrap stack; direct IAM queries confirmed both temporary tenant deployer roles no longer existed after that drill. |
| Management PostgreSQL | 31 passed | Enrollment replay/key possession, signed contiguous health, cross-process revocation, membership routing, concurrent quota limits and operation fencing used durable PostgreSQL. |
| Python managed/security selection | 55 passed, 8 skipped before PostgreSQL; skipped cases then passed in the 31-test durable suite | Managed authorization, envelope, lifecycle, reasoner and storage regressions passed. |
| TypeScript agent | Typecheck/build, 19 focused managed/data readiness tests and 31 domain tests passed | Worker waits for security/reasoner proxies before consuming the queue; Redis TLS/cluster-prefix and managed-envelope regressions passed. A broader run produced 1,103 passes and 65 failures because the sandbox denied local `127.0.0.1` listeners; those failures are not counted as product passes or failures. |
| Go BYOC | Tests and vet passed | Local command authority, outbox, CSR/TLS credential handling, certificate-chain/key/SPIFFE/client-auth validation and real/local provider validation compiled and passed. |
| OpenAPI/Postman | OpenAPI/collection parity tests passed; Postman reported “No issues found” then exited 139 in macOS keychain cleanup | All 21 operations, including certificate rotation, are present in the generated filesystem collection. The CLI process defect is not treated as a clean zero-exit run. |
| Domain namespace | Passed | Repository scan found no legacy product DNS or trust-domain references; examples and SPIFFE fixtures use Autobot domains. |

## T01–T17 disposition

| Test | Current evidence | Gate disposition |
|---|---|---|
| T01 | Colliding finding, case, evidence, comments, attachments, IOCs, joins, search/export and S3 objects were exercised with positive controls and unchanged foreign state. | Passed for the deployed isolation matrix; additional product data types require the same treatment as they are introduced. |
| T02 | Both managed positive connector paths succeeded; foreign tenant/body and altered exact-grant bindings were denied with unchanged unauthorized effects. | Passed for the deployed read-only connector matrix; production mutation connectors still require integration-specific qualification. |
| T03 | Dedicated workers/reasoners completed pinned DSPy runs; tenant-local memory returned only the owning canary; foreign canaries were absent from peer application logs. | Passed for the deployed triage path; future shared model services require separate context-isolation evidence. |
| T04 | Peer broker connectivity was denied. Exact signed redelivery completed as an idempotent no-op, while an altered envelope entered BullMQ's failed set; both produced zero new ledger events or connector effects. | Passed for the deployed queue/replay matrix. |
| T05 | Wrong issuer, wrong audience, expired sessions, revoked membership and logged-out-session replay were denied in both tenants. | Passed for the deployed managed-session matrix. |
| T06 | Positive finding and memory grants succeeded; every execution, tenant, deployment, incarnation, workflow, program, action, resource, argument, policy, epoch, workload, claim, bound, expiry and request-body substitution was denied. | Passed for the deployed read-only grant matrix; approval-required mutation connectors retain their separate lifecycle evidence. |
| T07 | Database-backed OIDC/SAML, SCIM, exact-scope JIT, break-glass, expiry/revocation and customer-visible audit passed local managed qualification after this AWS run. | Partial; external IdP interoperability and the mTLS support-gateway path have not been redeployed or qualified in these AWS environments. |
| T08 | Local signed-command unit coverage | Not run against a deployed outbound connector. |
| T09 | Durable bounded local outbox implementation | Not run as a long management partition with the deployed tenant runtime. |
| T10 | Cancellation/revocation across a gateway restart | Partial; active connector/session/credential rotation matrix remains. |
| T11 | Atomic failed image rollout | Partial; schema expansion/migration checkpoint failures remain. |
| T12 | Dedicated A/B load threshold passed | Partial for the product; shared-control saturation and budget-store failure remain. |
| T13 | Artifact digest pinning and irreversible revocation | Partial; the dataset/evaluation/optimization/promotion lifecycle and aggregate BYOC receipt are implemented and locally tested after this AWS run. They have not been redeployed or qualified in these two AWS environments. |
| T14 | Runtime database credentials were denied protected-table access in both tenants; peer broker paths were denied and foreign state stayed unchanged. | Passed for the deployed database/broker matrix; additional observability backends require the same direct credential tests when deployed. |
| T15 | Peer application-container logs contained no foreign observability canary after the complete matrix. Durable management/BYOC audit paths and the same-account offboarding report remain available separately. | Passed for deployed application-log canaries; customer-visible export and retention/deletion drills remain. |
| T16 | Exact Aurora restore, S3 version deletion, two dedicated-stack deletion drills, provisioning-role deletion and same-account BYOC resource deletion | Passed for the tested dedicated data shapes and BYOC resource fixture; regional restore, legal hold and the full application backup set remain. |
| T17 | Separate roles/VPCs in one provider-owned account | Not passed for BYOC; a customer-owned account, SCP/customer admin controls and central-role revocation are required. |

## Commands

```bash
export VIGIL_AWS_ACCOUNT_ID='<authorized-development-account-id>'
export VIGIL_AWS_TRUSTED_PRINCIPAL_ARN='<approved-deployer-role-arn>'
export VIGIL_CONTROL_PLANE_CIDR='<qualifying-host-public-ip>/32'
export AUTOBOT_AWS_ACCOUNT_ID="$VIGIL_AWS_ACCOUNT_ID"
./infra/production-qualification/aws/qualify.sh preview
./infra/production-qualification/aws/qualify.sh apply
python3 infra/production-qualification/aws/runtime-qualify.py
python3 infra/production-qualification/aws/boundary-qualify.py
python3 infra/production-qualification/aws/lifecycle-qualify.py
python3 infra/production-qualification/aws/recovery-qualify.py
python3 infra/production-qualification/aws/rollback-qualify.py
python3 infra/production-qualification/aws/load-qualify.py
./infra/production-qualification/aws/qualify.sh isolation-qualify
./infra/production-qualification/aws/byoc-qualify.sh qualify
./infra/production-qualification/aws/qualify.sh offboard
# Recovery checkpoints for a partial offboard:
./infra/production-qualification/aws/qualify.sh offboard-a
./infra/production-qualification/aws/qualify.sh offboard-b
./infra/production-qualification/aws/qualify.sh bootstrap-offboard
./infra/production-qualification/aws/byoc-qualify.sh offboard
```

## Remaining business readiness

Do not accept live customer data from this report alone. External enterprise IdP
interoperability and deployed support-gateway qualification, billing/entitlements,
customer lifecycle automation, a continuous connector deployment with a real
management endpoint, multi-region recovery, full observability isolation, a live-provider
DSPy optimization and promotion drill in deployed AWS, and customer-owned AWS qualification
remain release blockers for the corresponding product surface.
