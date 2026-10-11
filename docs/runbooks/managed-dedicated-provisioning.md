# Managed dedicated provisioning

Status: operator runbook for the Phase 3 checkpoint. It does not authorize customer
data or claim AWS qualification.

## Required roles

- **Binding administrator:** registers the tenant, deployment-specific account binding,
  artifact approvals and operator scopes. This role does not receive customer data-plane
  credentials.
- **Deployment requester:** may submit lifecycle operations for its server-side tenant
  scope.
- **Deployment approver:** a different issuer-qualified subject who approves the exact
  manifest digest and Pulumi plan hash.
- **Reconciler:** a workload with an mTLS certificate containing exactly the SPIFFE URI
  registered in the trusted binding. Its AWS role is restricted to the bound account.

## Preflight

1. Allocate a unique tenant ID, deployment ID and incarnation. Never reuse them after
   deletion. Create a dedicated AWS account or approved dedicated account boundary.
2. Create a least-privilege provisioning role with an external ID and constrain its
   trust to the reconciler identity. Record its account, region and role only in the
   trusted binding; do not place them in the deployment manifest.
3. Allocate isolated Pulumi state, secrets provider, Pulumi home and workspace. Issue a
   receipt signing key and reconciler client certificate. Store private material in the
   reconciler secret store with file permissions restricted to its runtime identity.
4. Choose at least two availability zones and non-overlapping public/private subnets
   within the bound VPC CIDR. Confirm the state backend, artifact mirror and management
   endpoint use approved TLS and private access paths.
5. Approve exact application, harness, infrastructure, policy, DSPy and compatibility
   SHA-256 references. Confirm the infrastructure source-tree digest matches the
   manifest's infrastructure reference.
6. Compute the materialized binding's RFC 8785 digest with
   `go run ./cmd/json-digest /run/vigil/bindings/deployment.json`. Apply
   `infra/management/database/001_management_plane.sql` with a migration role.
   In one audited administrative transaction, register the tenant, account binding,
   binding digest, artifact approvals and issuer-qualified operator scopes. The management service
   runtime role receives only DML needed by `services/management/store.py`.
7. Start the management service with its PostgreSQL URL, JWT issuer/audience/public key,
   command-signing key, server certificate/key and client CA. `services.management.serve`
   requires client certificates at TLS and fails startup when required configuration is
   absent.

## LocalStack development profile

Use the LocalStack profile for executable development and pull-request evidence before
requesting any AWS account access:

```sh
./infra/phase3-aws/localstack/qualify.sh managed
./infra/phase3-aws/localstack/qualify.sh down
```

The harness owns only the `vigil-phase3-localstack` compose project and its state under
`/tmp/vigil-phase3-localstack` by default. It starts separate A/B emulator processes,
uses synthetic credentials, creates distinct file-backed Pulumi state and staged source
workspaces, generates short-lived CA/JWT/command/receipt trust material, and runs the
durable two-person management lifecycle plus positive controls before negative controls. Set
`PHASE3_LOCALSTACK_WORK_ROOT` to relocate the transient work root.

Do not copy a LocalStack binding into production. Its loopback endpoint, synthetic
account, passphrase provider and file backend are rejected by the `aws` execution
profile and provide no AWS qualification evidence.

## Provision

1. Validate the manifest against `contracts/deployment-manifest.schema.json` and the
   Python and Go contract tests. Retain the exact RFC 8785 canonical digest.
2. Submit `POST /v1/deployments/{deployment_id}/operations` with a unique bounded
   `Idempotency-Key`. The API derives operator authority from the verified JWT and
   resolves the tenant target, account binding and artifact approvals in PostgreSQL.
3. Read the durable operation ID. Start the bound reconciler in `plan` phase. It claims
   the operation over mTLS, verifies the signed command, stages only the approved source
   tree in an isolated workspace, and writes a Pulumi saved plan.
4. Compare the plan with the approved architecture and expected tenant/account/region.
   The requester cannot approve it. A distinct deployment approver submits the exact
   manifest digest, plan hash and a bounded future expiry.
5. Start the reconciler in `apply` phase. It must use the saved plan whose SHA-256 equals
   the approved plan hash. A different or missing plan is a hard failure.
6. Accept success only after the reconciler signs a receipt bound to operation,
   command, deployment, tenant, fence, manifest, plan and generation. Confirm the
   management operation is `succeeded` and observed generation equals target generation.
7. Before enabling ingestion, run the deployed release/health checks and the applicable
   T01-T17 positive and negative controls. Confirm denied cross-deployment attempts
   leave foreign state and sink counters unchanged.

## Failure handling

- Do not retry with a new manifest under the same idempotency key.
- A failed plan/apply enters `recovery_required`; a new claim receives a new command ID
  and fences callbacks from the prior command.
- Cancel only through the management API. Cancellation advances the deployment fence,
  clears the desired generation back to observed state and rejects stale results.
- Provider uncertainty is not success. Inspect Pulumi state and cloud audit records,
  reconcile the exact operation, then retry the original phase or quarantine it.
- Never bypass the approved saved plan with a direct `pulumi up`, Helm command or AWS
  console edit. Emergency changes require an incident record and later state repair.

## Evidence to retain

Retain the manifest and canonical digest, account binding identifier (without secrets),
artifact digests, operation/event IDs, requester and approver subjects, command IDs,
fencing tokens, saved-plan hash, Pulumi update ID, signed receipt, sanitized inventory,
  test fixture version, T01-T17 outcomes and any recovery decision.
