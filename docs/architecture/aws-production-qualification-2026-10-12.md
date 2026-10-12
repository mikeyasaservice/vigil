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
| Helm | chart/app 0.7.0; A revision 7 after an atomic rollback, B revision 5 |
| Backend image | qualification r4, digest `sha256:17e19b7f1de2cc1fe43901d7fc9c614de6a312591c2c2f4fd2e24e697c863c5b` |
| Agent image | qualification r5, digest `sha256:75495b2f1e075c32ed72ebdc316164a4f671485a9d07825b0af229e16b107c20` |
| Connector image | qualification r4, digest `sha256:ffce126da236cf80dec354a83a8e5fea04540ed5c3e92b97cbae515f0da8cb74` |
| Reasoner image | qualification r4, digest `sha256:8265e711be952188c3140182a1b95029356b8f270a84d1be281693148856ce9f` |
| Tooling | Pulumi 3.244.0, Helm 4.3.0, kubectl 1.37.0, AWS CLI 2.34.37, Go 1.27.1 |

The source baseline was commit `2de0de7`. The qualification fixes and harnesses
described here were uncommitted during execution and are part of the commit that
adds this report. Raw evidence remains in the mode-0700 local qualification
roots under `/tmp/vigil-aws-qualification` and
`/tmp/autobot-byoc-qualification`; those paths contain account-specific resource
identifiers and are intentionally not committed.

## Executed evidence

| Evidence | Result | Exact narrow claim |
|---|---|---|
| Runtime `20261012T015858Z` | Passed | Distinct colliding findings; A and B each completed a pinned DSPy managed investigation; foreign token and tenant-header substitution denied. |
| Boundaries `20261012T015921Z` | Passed | Workload identities read only their own secret; deployment roles could not read the other secret; own DB/cache positive controls connected while foreign private endpoints resolved but did not connect; worker direct backend/connector paths and worker-token-only legacy invocation were denied. |
| Lifecycle `20261012T020024Z` | Passed | Exact two-person approval binding; altered approval rejected; durable cancellation survived security-service restart; interrupted execution resumed with the original program digest; revoked program tombstone could not be deleted or reactivated. |
| Recovery `20261012T020527Z` | Passed | An Aurora snapshot restored into a private quarantine cluster with identical finding canary, table counts, run digest and ledger digest; the temporary restore was removed. A versioned KMS S3 object was deleted by exact version and became unreadable. |
| Rollback `20261012T022826Z` | Passed | A nonexistent agent image caused Helm revision 6 to fail; atomic rollback produced revision 7 with the exact previous image; both A and B completed managed investigations afterward. This did not exercise schema-migration rollback. |
| Load `20261012T024345Z` | Passed | During 48 concurrent A admissions, all 50 B reads succeeded with 0.637-second p95 against a declared 2-second threshold, and B completed an investigation in 2.49 seconds against a 180-second threshold. |
| BYOC AWS `20261012T024229Z` | Passed narrowly | In the same development account, KMS rotation, S3 KMS encryption/versioning, SQS KMS binding, an empty secret reference and an exact versioned object worked. This is not customer-owned-account evidence. |
| BYOC offboarding `byoc-offboard.json` | Passed narrowly | Direct AWS queries confirmed both S3 buckets and the SQS queue were gone, and the integration secret and KMS key were gone or in AWS scheduled-deletion state. This remains same-account development evidence. |
| Dedicated offboarding `offboard-a.json`, `offboard-b.json` | Passed | Pulumi deleted 92 resources per tenant. Direct queries confirmed EKS, Aurora, manual Aurora snapshots, Valkey, VPC, S3, runtime secret, KMS key, six ECR repositories and the workload IAM role were deleted or in the documented AWS scheduled-deletion state. |
| Qualification authority offboarding `offboard-bootstrap.json` | Passed | Pulumi deleted the 10-resource bootstrap stack; direct IAM queries confirmed both temporary tenant deployer roles no longer exist. |
| Management PostgreSQL | 31 passed | Enrollment replay/key possession, signed contiguous health, cross-process revocation, membership routing, concurrent quota limits and operation fencing used durable PostgreSQL. |
| Python managed/security selection | 55 passed, 8 skipped before PostgreSQL; skipped cases then passed in the 31-test durable suite | Managed authorization, envelope, lifecycle, reasoner and storage regressions passed. |
| TypeScript agent | Typecheck/build, 19 focused managed/data readiness tests and 31 domain tests passed | Worker waits for security/reasoner proxies before consuming the queue; Redis TLS/cluster-prefix and managed-envelope regressions passed. A broader run produced 1,103 passes and 65 failures because the sandbox denied local `127.0.0.1` listeners; those failures are not counted as product passes or failures. |
| Go BYOC | Tests and vet passed | Local command authority, outbox, CSR/TLS credential handling, certificate-chain/key/SPIFFE/client-auth validation and real/local provider validation compiled and passed. |
| OpenAPI/Postman | OpenAPI/collection parity tests passed; Postman reported “No issues found” then exited 139 in macOS keychain cleanup | All 21 operations, including certificate rotation, are present in the generated filesystem collection. The CLI process defect is not treated as a clean zero-exit run. |
| Domain namespace | Passed | Repository scan found no legacy product DNS or trust-domain references; examples and SPIFFE fixtures use Autobot domains. |

## T01–T17 disposition

| Test | Current evidence | Gate disposition |
|---|---|---|
| T01 | One colliding finding and DB boundary | Partial; cases, evidence, search/export and signed object substitution remain. |
| T02 | Secret/workload isolation and worker network bypass | Partial; an authorized connector positive effect and foreign sink zero-effect matrix remain. |
| T03 | Separate workers/reasoners and completed DSPy runs | Partial; adversarial memory/cache/history/model-sink canaries remain. |
| T04 | Durable resume idempotency and pinned program | Partial; forged broker/DLQ/cache collision matrix remains. |
| T05 | Foreign token and tenant header denied | Partial; full issuer/audience/session/membership expiry matrix remains. |
| T06 | Worker bypass denied and bound two-person approval | Partial; all grant substitutions against a deployed mutation sink remain. |
| T07 | Database-backed OIDC/SAML, SCIM, exact-scope JIT, break-glass, expiry/revocation and customer-visible audit passed local managed qualification after this AWS run. | Partial; external IdP interoperability and the mTLS support-gateway path have not been redeployed or qualified in these AWS environments. |
| T08 | Local signed-command unit coverage | Not run against a deployed outbound connector. |
| T09 | Durable bounded local outbox implementation | Not run as a long management partition with the deployed tenant runtime. |
| T10 | Cancellation/revocation across a gateway restart | Partial; active connector/session/credential rotation matrix remains. |
| T11 | Atomic failed image rollout | Partial; schema expansion/migration checkpoint failures remain. |
| T12 | Dedicated A/B load threshold passed | Partial for the product; shared-control saturation and budget-store failure remain. |
| T13 | Artifact digest pinning and irreversible revocation | Partial; the dataset/evaluation/optimization/promotion lifecycle and aggregate BYOC receipt are implemented and locally tested after this AWS run. They have not been redeployed or qualified in these two AWS environments. |
| T14 | Secret IAM and network isolation | Partial; logs, metrics, traces, alerts and support exports remain. |
| T15 | Durable management/BYOC audit unit/integration paths plus same-account BYOC offboarding report | Partial; customer-visible export and retention/deletion drill remain. |
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
