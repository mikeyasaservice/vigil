# Phase 5 BYOC implementation

Status: **outbound connector and real-AWS resource paths implemented; real
customer-cloud and production readiness are not approved**.

Phase 5 installs the same dedicated tenant runtime boundary in a customer-owned
account. The provider management plane receives deployment metadata and
allowlisted health only. It does not receive integration credentials, findings,
prompts, evidence, model context or customer Pulumi state.

## Checkpoints

| Checkpoint | State | Evidence and remaining work |
|---|---|---|
| Customer account installer | LocalStack and same-account AWS qualification implemented | Pulumi Go separates `localstack`, real `aws`, and explicitly labeled `aws-qualification` modes. Real `aws` refuses the platform account. KMS rotation, versioned encrypted buckets, KMS SQS and an empty secret reference passed in the development account. A customer-owned account remains required for T17. |
| Connector enrollment | Implemented and tested locally | An operator creates a 15-minute, retry-stable, one-use enrollment bound to tenant, deployment, AWS account, connector SPIFFE URI and local policy digest. Consumption requires verified mTLS identity plus proof of the connector's locally generated Ed25519 private key. The connector submits a local P-256 CSR; the control plane returns a 24-hour client-only certificate bound to the authenticated SPIFFE URI. Private keys never leave the customer data plane. |
| Local command authority | Implemented and unit tested | The customer-side Go authority verifies signed commands against its account, tenant, deployment, incarnation, policy, trust version, revocation epoch, sequence and central lease. Release, policy and support actions consume an exact distinct-customer approval. Release digests are pinned. |
| Disconnection and emergency revoke | Implemented locally | Authority is Ed25519-sealed, atomically persisted and fsynced. Local emergency revocation survives restart, altered state is rejected, and even valid central signatures cannot bypass it. The health outbox is bounded to 128 records and coalesces overflow into a signed contiguous gap marker. Detection/runtime wiring and long-duration partition tests remain. |
| Outbound health | Daemon and persistence implemented | Connector health uses mTLS plus an event signature, contiguous sequence and current revocation epoch. The continuous daemon persists before send, retries with bounded backoff, acknowledges oldest-first, reloads rotated certificates, and retains a bounded gap-marking outbox. A deployed management endpoint and long-duration partition qualification remain. |
| Recovery/offboarding | Not qualified | Versioned backup storage exists as a resource fixture. Restore, key-custody, deletion receipts, quarantined recovery and customer-run offboarding drills remain required. |

## API and state contract

- `POST /v1/byoc/enrollments` requires a server-resolved operator scope. It
  returns the enrollment bearer once; PostgreSQL stores only its SHA-256 digest.
- `POST /internal/v1/byoc/enroll` requires the pre-trusted bootstrap mTLS
  identity and proof of the connector signing key. Dynamic CSR issuance is not
  implemented by this checkpoint.
- `POST /internal/v1/byoc/deployments/{deployment_id}/health` accepts only the
  closed aggregate schema, exact deployment SPIFFE identity, current incarnation
  and revocation epoch, a valid signature and the next sequence.
- `POST /v1/tenants/{tenant_id}/deployments/{deployment_id}/byoc/revoke`
  durably disables central connector access and advances its epoch. Customer
  local emergency revocation is independent and remains authoritative offline.

## Boundary record

- **Tenant boundary:** one BYOC connector binding targets one immutable tenant,
  deployment and customer AWS account. The installer creates only customer-owned
  resource references and retains dedicated runtime/data boundaries.
- **Identity source:** operator issuer/subject comes from the verified management
  JWT and durable scope. Connector identity comes from the verified mTLS SPIFFE
  URI plus possession of a locally generated Ed25519 key. Request fields do not
  establish ownership.
- **Secret/data flow:** the control plane stores connector public keys, policy
  digests, revocation/sequence metadata and allowlisted aggregate health. The
  enrollment HMAC key is mounted control-plane trust. Customer secrets and data
  remain in customer resources; Pulumi exports secret references, never values.
- **Failure behavior:** missing trust, stale or reused enrollment, wrong account,
  foreign certificate, altered signature, sequence gap, old epoch, expired lease,
  missing customer approval or unavailable durable state denies new central
  action. Management disconnection does not clear local policy or revocation.
- **Readiness tests:** local evidence exercises parts of T08, T09, T10, T11 and
  T15. T16 resource shape is present but restore is not run. T17 and full AWS
  IAM/network qualification remain open.
