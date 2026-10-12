# Phase 3 validation evidence

Status: **implementation checkpoint; production qualification NOT RUN**.

Date: 2026-10-11. Branch: `codex/phase3-managed-dedicated-mvp`. Baseline Phase 2
commit: `c84640f`.

This report covers the management-plane and dedicated infrastructure checkpoint,
including the required LocalStack development profile. It does not claim a
customer-ready managed service. No AWS account preview or apply, Helm release
installation, backup/restore drill, offboarding drill or production T01-T17
qualification was performed.

## Implemented evidence

| Boundary | Identity and authority | Enforced behavior | Evidence | Tests prepared |
|---|---|---|---|---|
| Operator API | Configured JWT issuer/audience/public key plus issuer-qualified subject; durable tenant/global role scope | No tenant authority from manifest/path/header; distinct requester/approver; exact manifest and plan approval | `services/management/auth.py`, `store.py`, management migration and OpenAPI | T05, T07, T17 |
| Reconciler API | TLS server requires client certificate; a server adapter copies one SPIFFE URI from the verified peer certificate into per-connection ASGI state and the API matches it to the trusted binding | Spoofed identity headers have no authority; wrong deployment workload denied | unit tests plus real TLS A-certificate/B-operation denial | T07, T08, T17 development evidence |
| Operation state | PostgreSQL transaction, idempotency key, generation, deployment lock, fence, lease and outbox | Altered reuse, stale generation, concurrent mutation and stale claimant fail closed | real PostgreSQL lifecycle test | T08, T11, T17 |
| Command/result | Ed25519 command and receipt signatures over RFC 8785 JSON; persisted command ID | Expired/tampered/wrong-phase commands and callbacks from older commands are denied | Python/Go protocol code and tests; real receipt transaction | T08, T11, T17 |
| Provisioning target | Admission-pinned trusted-binding digest plus explicit Pulumi AWS provider with allowed account and fixed AssumeRole/external ID | Manifest cannot select role, account, state backend, raw network or credentials; binding mutation and substitution are rejected before provider execution | shared Unicode/cross-target Go tests | T08, T17 |
| Dedicated resources | Deployment-specific stack, workspace, VPC, private EKS and nodes, Multi-AZ RDS, HA Redis, S3 and KMS | Resource names/tags and provider are deployment-bound; protected data resources require deliberate deletion | Go component builds and unit tests | T01-T04, T11-T17 |
| LocalStack development targets | Trusted profile in the binding, loopback-only endpoint, synthetic credentials, disabled ambient config/metadata discovery, isolated emulator and Pulumi state per tenant | The profile cannot carry an AWS role/external ID; customer manifests cannot select endpoints; unsupported EKS/RDS/ElastiCache resources are not represented as created | Two real LocalStack applies and boundary probes described below | T08, T17 development evidence |

## LocalStack managed development qualification

`infra/phase3-aws/localstack/qualify.sh managed` was executed on 2026-10-11 with Pulumi
3.244.0, AWS provider 7.50.0 and two healthy `localstack/localstack:4.8.1`
containers. The resolved image ID was
`sha256:8c9756bddc44625cd6e890f5e4bcc29b045eebe108b268482b848f4f832ec153`.
Each container was exposed only on loopback, at ports 4566 and 4567, and used its own
persistent volume. Each tenant also used a separate Pulumi home, file backend and
staged source workspace. A healthy `postgres:16-alpine` container with image ID
`sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
held management state.

The harness generated a CA, server certificate, tenant-specific SPIFFE client
certificates, operator JWT key, management command key and tenant receipt keys. It
submitted A/B operations over the TLS service. Tenant A's certificate received 403
when claiming Tenant B's operation. Each bound reconciler then claimed plan work,
verified a signed command, produced a saved Pulumi plan, and returned the plan hash.
A different tenant-scoped subject approved the exact manifest and plan before the
reconciler claimed apply work. Signed receipts advanced both deployments to active,
observed generation 1.

Tenant A's manifest, plan and receipt digests were respectively
`c37df8ed90dc7815594040eb20527f6ba19ed2113f18ce692dc097f6c9b4a568`,
`ed71a5970f2ce99fb0250b1c682c5bead632a0dd4f701007b1d58dd2fea57dcc`
and `bb8ea41436e5fbcb1d65f8b00f9b93cc44211c2d3cef23fa1364a57b6350fa34`.
Tenant B's were
`c38fb457ffbcf44aa3155322e586ba176042ca55609d2b65e9a6d9d15a284d41`,
`5c537991e1f0b344e0c5981ce3b2c72383ff7cc10c9444603531482075d9e60d`
and `9134bdfe4b47c5c07bfb6877aead3abbf3331e4e3ef5a9d428849f6acc872141`.
Each operation recorded two claims and six ordered lifecycle events.

Pulumi applied 13 resources to each target: an explicit AWS provider, component, VPC,
two private subnets, KMS key, versioned KMS-encrypted S3 bucket, Secrets Manager
secret/version and KMS-encrypted SQS queue.

The positive controls wrote and read distinct canaries through each tenant's endpoint.
The negative controls established that A's endpoint could not address B's bucket and
B's endpoint could not address A's bucket. An A manifest paired with B's trusted
binding failed during program validation with `manifest target does not match the
trusted binding`, before provider mutation. Complete A/B inventory digests remained
unchanged across the negative tests:

- Tenant A: `1328290b71313894abe9008ffd6e2b39a6dc663df1b5596c5db1144e128ca1d6`
- Tenant B: `f646b4ab4d214fafa7f70e328c48570aceb8e51be79e12cf030bcc42a672d118`

This result validates the implemented development target selection and provider
interactions. LocalStack uses synthetic account `000000000000` and cannot qualify AWS
account/IAM enforcement, EKS/RDS/ElastiCache behavior, host isolation, backup/recovery
or customer readiness.

## Commands and results

| Command | Result |
|---|---|
| `go test ./...` in `infra/phase3-aws` | PASS: reconciler and spec packages; other packages compile |
| `go vet ./...` in `infra/phase3-aws` | PASS |
| `infra/phase3-aws/localstack/qualify.sh managed` | PASS: real TLS service, foreign certificate denial, durable A/B admission, saved-plan approval/apply, signed receipts, positive A/B S3 controls, cross-endpoint denial, cross-binding denial and unchanged inventories |
| Python management contract, readiness, operator JWT and workload-identity tests | PASS: 11 tests |
| Python management PostgreSQL lifecycle test | PASS: 1 test against disposable PostgreSQL after applying the migration from a clean schema |
| `python3 -m py_compile services/management/*.py` | PASS |
| Management image build | PASS: non-root image built from pinned `python:3.12-slim` digest; local image digest `sha256:8b3f65934e115f255ec3b4687bddc8e4b2217cc5059563e6e7f1df84ebd9ec1c` |
| Missing-configuration container startup | PASS: failed closed at absent management database configuration |
| Postman/OpenAPI parity assertion | PASS inside Python contract suite |
| Helm lint and managed network-policy render | PASS |
| Phase 2 Python managed regressions | PASS: 28 tests; one existing SQLAlchemy deprecation warning |
| Phase 2 TypeScript managed regressions | PASS: typecheck and 38 tests |
| Postman CLI schema lint/generation | NOT RUN: local CLI failed before parsing due macOS Keychain `SecItemCopyMatching -50`; collection was generated by the committed filesystem script and parity-tested |

The PostgreSQL test executes: provision admission, plan claim, wrong-command replay
denial, valid plan result, requester self-approval denial, distinct approval, apply claim,
signed receipt commit, observed-generation advancement, second-generation cancellation
and stale result denial.

## T01-T17 gate status

All T01-T17 remain **NOT RUN against the Phase 3 cloud deployment**. Unit, contract,
container and local PostgreSQL results above are supporting evidence only.

| Gate group | Current state | Required next evidence |
|---|---|---|
| T01-T06 | NOT RUN | Deploy A/B application, worker, database, Redis, reasoner, gateway, connector and sinks; run positive and cross-target probes with colliding fixtures. |
| T07-T08 | T07 local managed qualification PASS; cloud NOT RUN | Redeploy the mTLS support gateway in AWS and exercise JIT/expiry/revocation plus signed-command tamper/replay against cloud audit logs. |
| T09-T10 | NOT RUN | Partition management, expire central authority, restart data-plane services and measure the durable local revocation boundary. |
| T11-T13 | NOT RUN | Install pinned releases; inject upgrade failures and resource pressure; verify program/policy rollback and unchanged peer SLO/state. |
| T14-T15 | NOT RUN | Use real runtime database/IAM roles and inject canaries into logs, metrics, errors and support exports. |
| T16 | NOT RUN | Complete backup, quarantine restore, current-tombstone application, legal hold and deletion receipt drills. |
| T17 | NOT RUN | Preview/apply two trusted account bindings, attempt cross-account/role/state/network substitution, race/take over reconciliation and inspect zero foreign mutations. |

## Known blockers before customer data

- The Pulumi component has not been previewed against a real bound AWS account.
- The managed Helm application release, workload IAM roles, runtime network policy and
  deployed probes are not yet part of the cloud apply.
- Backup inventory, quarantine restore, regional recovery and offboarding receipts are
  procedures only.
- No customer product inputs are approved for identity provider, ingress, regions,
  retention, support access, model egress, RPO/RTO or SLA.
- LocalStack and a shared developer host provide executable development evidence only;
  they cannot qualify AWS account, IAM, EKS, RDS, ElastiCache, host, recovery or
  operator boundaries.

The next reviewable development checkpoint is the pinned Helm application release,
runtime health oracle and upgrade/rollback controls on the two LocalStack-backed data
planes. A later production qualification still requires two dedicated AWS targets.
Only the exact scenarios executed may be marked passed.
