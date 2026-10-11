# BYOC reference architecture

Decision D06: the customer owns the account/project, network, persistent storage,
integration credentials, retention and encryption policy. The same tenant runtime used
in the managed dedicated service operates locally. The provider manages only the scope
the customer has explicitly delegated. See [diagram](deployment-models.md).

## Initial cloud assessment

| Candidate | Existing leverage / implementation work | Managed-service implications | Decision |
|---|---|---|---|
| AWS | Existing S3 access and Helm deployment; add account/VPC, workload IAM, KMS, RDS and storage adapters | Per-customer roles, private endpoints, account policy variation | First reference, provisional |
| Azure | Kubernetes/runtime portable; add managed PostgreSQL, Blob, Key Vault and workload identity bindings | Customer Entra/network policy and private endpoint integration | Next if signed customer demand warrants |
| GCP | Kubernetes/runtime portable; add Cloud SQL, object storage, KMS and workload identity bindings | Organization constraints, private connectivity and regional coverage | Next if demand warrants |

No customer demand evidence was provided. Prioritize using qualified pipeline count,
required regions, customer identity/network constraints, support skills, prototype
effort and projected support cost. Do not present AWS as a proven market preference.
Cloud-specific resources stay behind DeploymentAdapter, SecretResolver, object-store,
key-service and workload-identity interfaces; domain logic uses none of their ARNs.

## AWS reference

The first executable local checkpoint is recorded in
[Phase 5 implementation](phase5-implementation.md). It provisions customer-owned
resource shapes through LocalStack and exercises local connector authority. It
does not qualify real AWS IAM, networking, Kubernetes, RDS, backup recovery or
customer operations.

Customer bootstraps a versioned Pulumi Go program in their account, approves the preview,
retains encrypted/locked state locally and supplies the tenant/deployment registration.
Use a customer VPC, private application/worker subnets, dedicated EKS cluster or an
approved customer Kubernetes environment, RDS PostgreSQL, tenant-local Redis, S3,
Secrets Manager and KMS. Select exact SKUs after sizing; no cloud resources are created
in Phase 1. Private customer API access can use VPN/private routing or approved ingress;
AWS PrivateLink may be evaluated for management reachability where available. Outbound
HTTPS through an allowlisted proxy remains the first connector transport.

Assign distinct workload roles to local reconciler, runtime API, gateway/connectors,
backup and migration jobs. The reconciler must not have unrestricted `iam:PassRole`,
wildcard assume-role, tenant evidence reads or KMS decrypt. Customer-approved installer
authority can be broader than routine management, but it expires after bootstrap. If
cross-account access is chosen for a specific task, require an external ID, exact trusted
principal, short session, scoped resources and tested confused-deputy protection; never
copy long-lived keys centrally. [AWS third-party role guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html).

Egress policy separately covers management, artifact registry, DNS/time, model providers
and integrations. Registry mirrors and local models permit sensitive workloads without
external inference. Management-only outbound does **not** mean a cloud model receives
no telemetry; model egress is an independent customer decision enforced locally.

## Enrollment and management

Customer approves a one-use enrollment token bound to tenant, deployment, cloud account
and short expiry. The local connector generates its private key locally and submits a
CSR with workload/account proof. The control plane binds its certificate to exactly
that deployment. Bootstrap trust roots and release signer policy are customer-visible;
keys rotate with a bounded overlap and monotonic trust version. Certificate expiry
stops management, not local security. Recovery uses customer-approved re-enrollment,
not a permanently valid bootstrap secret.

The connector initiates mTLS long polling and submits allowlisted health/status records.
It retrieves signed desired state and verifies it locally using
[command semantics](control-plane-data-plane.md). New images, privileged support and
infrastructure mutations require local standing approval policy or explicit customer
approval. Keep app and infrastructure generations separate. Audit every accepted and
rejected administrative command in customer-owned storage.

## Management disconnection behavior

| Function | Disconnected behavior | Recovery |
|---|---|---|
| Detection / ingestion | Continue local schedules and known integrations under last valid installed policy; reserve capacity | Report backlog/health, reconcile cursors idempotently |
| Investigation / DSPy | Continue pinned approved programs using locally available model, context, budgets and local authority | No automatic program promotion or cross-tenant data upload |
| Privileged tool execution | Local standing policy and customer approvals can authorize; central-dependent grants expire without renewal; unknown authorization denies | Refresh revocations before resuming central-dependent actions |
| Local security policy | Retain installed restrictive policy and emergency deny controls; a transport timeout never makes it permissive | Accept only verified newer policy; never roll back revocation epochs |
| Identity | Local verifier/IdP path must be available; expired human sessions are not extended merely to preserve availability | Reauthenticate; do not replay old tokens |
| Health / metering | Bounded encrypted durable outbox, sequence + incarnation; aggregate/coalesce health under pressure | At-least-once resend; dedupe at management; acknowledge durably |
| Audit | Retain locally with capacity reservation; stop privileged dispatch if durable audit fails | Export only permitted metadata; no raw audit dump by default |
| Upgrades | Do not begin new remotely requested upgrades; an already accepted, fully staged operation reaches local safe checkpoint or rollback | Re-plan against current generation; stale queued command cannot apply |
| Support | No new central support sessions; existing sessions expire locally; customer-local admin still available | New approval required, never resurrect expired sessions |
| Revocation / emergency stop | Customer can revoke management cert/trust, disable local actions and rotate credentials offline | Re-enroll only with customer approval; deny epochs survive restarts/restore |

An unavailable model/provider limits investigation but does not disable deterministic
ingestion/detection or existing enforcement. Connectivity cannot deliver a central
revocation instantly; maximum exposure equals the remaining central authority lease,
with no offline renewal. Local emergency revocation is authoritative. Detailed event
queues must never grow without bound: after the configured storage watermark, pause
new expensive investigations while retaining policy, ingestion safety and audit space;
record an explicit loss/gap marker for discarded noncritical health data.

## Shared service responsibilities

Provider: signed releases, compatibility matrix, connector protocol, scoped fleet
operation, agreed support and notification. Customer: account ownership, network/IdP
availability, key approval, budget, integration access, retention and management
revocation. Joint: recovery drills, upgrade windows, incident access, model egress,
responsibility for cloud configuration drift and maintenance. Record these in each
deployment's service schedule before onboarding; account ownership alone is not an
operational SLA. [BYOC trust boundaries](../security/byoc-trust-boundaries.md).
