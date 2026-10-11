# Privileged operator access

Platform users can see permitted fleet metadata and request lifecycle operations.
They have no default tenant evidence session, integration credential, shell, database
login, agent grant or security-tool capability. Separate platform, tenant and workload
issuers/audiences prevent role-name collisions from becoming privilege escalation.

## Access workflow

1. Operator authenticates through workforce SSO with phishing-resistant MFA; record
   immutable subject, device/session assurance and ticket/purpose.
2. Request identifies one tenant/deployment, allowed actions/resources, justification,
   duration and any data export. Read-only diagnosis is the default scope.
3. Customer approval or explicitly agreed standing policy authorizes this exact scope;
   privileged/destructive access also requires independent provider approval. An
   operator cannot approve their own request. BYOC validates approval locally.
4. Local tenant authority issues a short-lived session bound to the operator/device,
   tenant, deployment, policy and approval. Initial ceiling: 15 minutes, with explicit
   reapproval/renewal. Tool capabilities remain separately authorized per invocation.
5. Audit every request, decision, session start/end, resource read, privileged action
   and export. Customer can inspect the local record and revoke the session immediately.
   Stop sessions on expiry/revocation, role removal or audit failure; cancel pending work.

Support access is not a blanket tunnel. Prefer bounded diagnostics and redacted support
bundles reviewed locally. Shell/database access, if necessary, is a separate break-glass
scope with recording, destination controls, approval and data handling requirements.
Avoid recording secret values; protect session recordings as tenant security data.

## Break glass and separation of duties

Keep an offline customer-controlled local emergency admin path for management outages.
Provider break glass requires a named incident, two authorized people, narrow scope,
short expiry, immediate notification and after-action review. BYOC customer revocation
or lack of prior approval cannot be overridden by a provider emergency account.

Separate release author, release approver, fleet deployer, support operator, migration
operator and key administrator roles. Fleet deployment privileges can indirectly grant
data access by changing code: constrain them to preapproved signed digests, admission
policy and workload roles; no arbitrary pod exec, manifests, host mounts or service
accounts. Audit and approve changes to those constraints as privileged operations.

Cloud root/organization administrators remain powerful in provider-hosted deployments.
Record and monitor their exceptional access separately; never equate absence of an
application login with inability to access data. Customer-managed key policies can
reduce scope but a runtime allowed to decrypt is still a sensitive authority.

Enterprise SAML/OIDC, SCIM deprovisioning, tenant RBAC, optional ABAC and workload identity
map into [identity context](../architecture/tenant-identity-context.md). Session/role
revocation must affect future actions and queued work, not only the next browser login.
T07/T10/T17 validate these rules, including operator attempts to bypass elevation through
fleet automation or a restored backup.
