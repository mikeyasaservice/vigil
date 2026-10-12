# Phase 5 AWS BYOC checkpoint

This project creates the customer-owned resource fixture and builds the local
authority connector. LocalStack remains the repeatable development path. An
explicit `aws-qualification` profile can exercise AWS services in the platform
development account, while the `aws` profile refuses that account and requires
a separately owned customer account.

The installer requires an explicit customer account ID and ownership
acknowledgement. It creates customer-tagged KMS, encrypted/versioned evidence and
backup buckets, an execution queue and an empty Secrets Manager reference. It
exports an exact runtime policy and never exports or creates a customer
credential value.

The connector stores its authority and bounded health outbox in a customer-owned
file, verifies management commands with Ed25519, consumes exact local approvals,
and persists emergency revocation across restarts. Its daemon uses outbound mTLS,
durably retries health events, enrolls from a local CSR, and rotates short-lived
certificates without sending the private key to the management plane.

`binding.example.json` demonstrates the closed local binding shape. Replace its
example management key with the customer-approved release signer before use.
Initialize and exercise the local emergency control with:

```bash
go run ./cmd/byoc-connector -action init -binding binding.example.json -state /tmp/vigil-byoc/authority.json -key /tmp/vigil-byoc/connector.key
go run ./cmd/byoc-connector -action revoke -binding binding.example.json -state /tmp/vigil-byoc/authority.json -key /tmp/vigil-byoc/connector.key
```

Requirements: Docker, Go, Pulumi and uv.

```bash
./infra/phase5-byoc/localstack/qualify.sh managed
./infra/phase5-byoc/localstack/qualify.sh down
```

Cleanup removes only the Phase 5 Compose project and volumes. Disposable Pulumi
state remains ignored under `.local-state/` for inspection.
