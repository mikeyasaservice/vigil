# BYOC trust boundaries

Management connectivity is an untrusted delivery path until both channel and command
verification succeed. A valid provider certificate is not unrestricted customer cloud
authority. [Reference architecture](../architecture/byoc-reference-architecture.md).

| Boundary | Trust / credentials | Allowed data and authority | Revocation owner |
|---|---|---|---|
| Customer bootstrap → local connector | Customer install approval, one-time registration, locally generated key | Enroll exactly one tenant/deployment/account | Customer |
| Connector → provider management | Deployment-bound mTLS certificate | Allowlisted health, revisions and metering; retrieve constrained signed commands | Either party can stop management |
| Provider signer → local command verifier | Pinned signer + customer trust policy | Target-bound commands within local policy and approvals | Customer local trust store; provider key revocation |
| Local reconciler → cloud/Kubernetes | Scoped workload role; no arbitrary PassRole or data decryption | Approved resource changes for one deployment | Customer IAM/admission policy |
| Tenant API → customer IdP/data stores | Tenant audience, membership, database/object roles | Tenant operations per role | Customer/local authority |
| Harness → capability gateway | Workload-bound execution grant | Exact tenant tool/resource/action/budget | Local authority/customer |
| Gateway → secret/integration service | Connector-specific local role | Selected short-lived credential, allowed operation | Customer/integration owner |
| DSPy → model endpoint | Approved model config, local credentials and egress | Only approved inference data; local model possible | Customer |
| Support → tenant resources | Separately approved local JIT session | Named diagnostics/actions, no automatic telemetry export | Customer/local authority |

## Required command defenses

Verify signer chain/key ID and allowed algorithm, canonical payload digest, audience,
tenant, deployment, installation incarnation, command type, expected generation,
monotonic sequence, expiry and exact approval binding. Reject unknown fields that could
alter security semantics. Persist duplicate detection before effects; cap envelope size
and queue depth. Unknown signer rotation cannot bootstrap itself from a command signed
only by the unknown key. Re-enrollment after revocation needs independent customer proof.

The outbound channel has no general reverse port forwarding, shell, filesystem upload,
raw SQL or arbitrary telemetry query. Release delivery uses pinned registries/mirrors,
digest verification and approved release policy. Protect against archive traversal and
executable deserialization when importing program artifacts.

## Customer controls and residual risk

Customer can block egress, revoke certificates/trust/roles, stop management reconciliation,
change keys, disable specific tool capabilities and trigger local emergency cancellation.
Separate **stop management**, **stop active response**, and **stop all discretionary
agents** from the safety services that continue ingesting/enforcing policy. Full runtime
shutdown is an explicit customer action, never an automatic response to an unreachable
management plane.

Installed restrictive policy remains enforceable offline. Local authority can renew
locally authorized execution grants; central-dependent support/command authority cannot
renew offline. Revocation freshness is local for local grants and lease-bounded for
central grants. A partition prevents instant delivery of new central revocations;
this limitation must be documented in customer service terms and tested in T09/T10.

A compromised control plane may publish malicious but validly signed software if its
release authority is also compromised. Mitigate with separated signers/approvers,
customer-approved artifact policies, local admission controls, rollout rings and audit.
Customer delegation of automatic installation remains a real supply-chain trust choice.
Customer cloud administrators and compromised hosts can also override local controls;
we do not claim protection against the customer's root authority.

No secret is copied centrally for operational convenience. Even secret references and
resource identifiers can be sensitive; export opaque IDs where possible. Detailed
diagnostics, evaluation examples and investigation traces remain customer-owned by
default. Test fixed health/export schemas with canary secrets and adversarial free text.
