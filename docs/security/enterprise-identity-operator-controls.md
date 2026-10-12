# Enterprise identity and operator controls

Status: **implemented and qualified in the disposable local managed environment; real
AWS and external identity-provider interoperability remain production gates**.

## Trust and identity model

The management plane accepts workforce identities from an explicitly configured OIDC
or SAML provider. OIDC validation uses a database-pinned JWKS, exact issuer and
audience, an allowed algorithm and key ID, bounded token lifetime, required claims,
and configured ACR or AMR assurance. SAML validation requires a signed assertion at
the expected document location, a pinned X.509 certificate, exact issuer, audience,
recipient and request correlation, bounded validity, authentication context and
one-time assertion use. The immutable principal is `provider_id:external_subject`.
Tenant IDs, roles and support privileges in a federation token are ignored.

SCIM 2.0 provisions and deprovisions workforce users and groups through an opaque,
provider-bound, expiring bearer credential stored only as a digest. SCIM establishes
identity state; it does not grant an active support session. Deactivating a user
revokes standing operator scope, pending requests and active sessions.

These choices follow the AWS Well-Architected Security Pillar guidance to use a
[centralized identity provider](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_identity_provider.html),
[temporary credentials](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_unique.html),
and [least privilege](https://docs.aws.amazon.com/wellarchitected/2023-10-03/framework/sec_permissions_least_privileges.html).

## Support access lifecycle

1. An MFA-assured, active federated operator requests exact actions and resources for
   one tenant and deployment. Wildcards are rejected.
2. An active tenant member with customer-approver authority approves the exact request
   digest. The requesting operator cannot approve it.
3. A separate provider approver approves the same digest. Break-glass access also
   requires a second distinct provider approver and an incident reference.
4. Activation returns a one-time opaque session secret. Only its SHA-256 digest is
   persisted. Normal support sessions expire within 15 minutes; break-glass sessions
   expire within 5 minutes.
5. Every action is authorized again against current database state. The call must
   present the federated operator identity, session secret, exact action/resource and
   an mTLS-authenticated support-gateway SPIFFE identity bound to the tenant deployment.
6. Customer or operator revocation, SCIM deprovisioning, suspension, offboarding,
   deletion, expiry or scope mismatch denies the next action.

Ordinary support scope is limited to health, diagnostic-bundle creation, audit reads
and backup metadata. Tenant-data reads, tool invocation, backup download, pod exec and
workload-role changes require explicit break-glass scope. This implements temporary
elevation and guardrails consistent with
[SEC03-BP05](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_define_guardrails.html).

## Audit and failure behavior

Requests, approvals, activation, each allow/deny decision and revocation are written to
a customer-visible append-only audit chain. Every record commits to the prior record
hash and canonical event data. Application updates and deletes are blocked by a
database trigger. Audit persistence is part of authorization; failure does not produce
authority or a successful dispatch. Logs and customer audit should follow
[SEC04-BP01](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html).

The support gateway binding comes from a signed, fenced deployment reconciliation
receipt. A request header cannot select a workload identity. The internal authorization
endpoint is reachable only through verified mTLS state supplied by the server TLS
adapter. The legacy static-token adapter is rejected at managed-service startup.

## Readiness evidence and limits

T07 development qualification passed in the disposable two-tenant LocalStack/PostgreSQL
environment. It proved the normal two-person flow, break-glass three-person flow,
short expiry, customer revocation, SCIM deprovisioning, tenant/deployment gateway
binding, five dangerous-action denials, foreign-resource denial and customer-visible
allow/deny audit. The management test suite and OpenAPI/Postman contract checks also
passed. See the dated [T07 validation report](../architecture/enterprise-identity-t07-validation-2026-10-12.md).

This does not pass production T07. Remaining evidence requires interoperability with
the selected enterprise IdPs, a deployed AWS support-gateway workload using production
certificate enrollment/rotation, customer-visible audit export/retention, and the same
adversarial cases in dedicated AWS and customer-owned BYOC accounts. Related readiness
tests are T05, T07, T10 and T17.
