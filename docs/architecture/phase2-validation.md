# Phase 2 secure execution foundation

Status: **remediation locally qualified; production readiness remains blocked**.
Branch: `codex/phase2-secure-execution`.
Qualification date: 2026-10-11.

This phase implements and exercises one managed investigation path:

```text
authenticated user
  -> server-resolved tenant membership and deployment
  -> durable admission and outbox
  -> signed exact-work queue envelope
  -> SPIFFE-authenticated worker claim
  -> execution-bound grant
  -> tenant-local capability gateway
  -> tenant connector and PostgreSQL read
  -> pinned DSPy triage program
```

The local qualification environment is evidence for these exact scenarios. It is
not evidence that kind provides production host isolation, that LocalStack enforces
AWS IAM, that the synthetic model endpoint represents a production model provider,
or that Phase 3 operational and customer-readiness gates have passed.

## Boundary and failure behavior

| Concern | Implemented boundary | Identity source and data flow | Fail-closed behavior | Readiness tests |
|---|---|---|---|---|
| User admission | Tenant-local API and security tables | Issuer-qualified immutable user ID; active membership and deployment resolved in PostgreSQL | Unknown, conflicting, revoked, or non-unique membership is denied before enqueue | T04, T05 |
| Queue work | Tenant Redis and signed envelope v3 | Admission, execution, run, reason, workflow/program digests, request/finding digests, incarnation, and expiry | Missing, unsigned, altered, foreign, expired, replayed, or revoked work is denied before ledger/model access | T04, T05, T10, T13 |
| Workload claim | SPIRE SVID and Envoy mTLS | Envoy strips identity headers and injects the verified worker URI SAN over a pod-local hop | A header, shared token, wrong SVID, fenced claim, or unavailable durable state cannot claim or dispatch | T05, T06, T10 |
| Tool dispatch | Tenant security service and connector | Signed execution attestation and grant bind tenant, deployment, execution, claim, workload, policy, epoch, action, resource, arguments, and bounds | Authorization audit and atomic budget reservation precede connector effects; uncertainty is not replayed | T02, T06, T10, T12 |
| Approval | Tenant-scoped durable lookup | Authorized approver membership; action/resource/argument/policy/expiry binding; requester and approver differ | Self-approval, altered arguments, missing checkpoint, expiry, or cancellation is denied | T06, T10 |
| Reasoning | Tenant reasoner and signed program registry | Reviewed artifact, manifest, dependency digest, model config, owner, approval, and execution pin | Altered, foreign, unapproved, unpinned, or revoked program is refused; reasoner cannot execute tools | T03, T13 |
| Data and secrets | Separate A/B application, database, Redis, connector, reasoner, LocalStack, credentials, and keys | Colliding finding IDs resolve through the tenant connector; workers receive no integration or LocalStack credentials | Worker direct egress and every foreign-tenant route are denied by Cilium | T01, T02, T03, T06 |

Managed startup also refuses development authentication bypass, missing deployment
binding or trust material, fail-open revocation, and unrestricted managed execution.
Standalone behavior and frozen v1 contracts remain behind explicit adapters.

## Deployed evidence

The disposable cluster used kind node image `v1.37.0`, Cilium `1.20.1`, SPIRE
chart `0.30.0` / app `1.14.5`, and LocalStack `4.8.1`. Tenant A and B run in
separate namespaces on separate kind worker nodes with separate PostgreSQL, Redis,
API, security service, worker, connector, reasoner, signing material, and
LocalStack processes. The host kernel is shared.

The deployed application images were:

```text
agent:   sha256:65235a95b289c7a486414c92be328c9562bf68d8d1f76bc54030fe58d9dbfff9
backend: sha256:8ad3e34273273527c89669c97f6ab1b10222e89a289565455a1c30bdb4d7111f
```

The pinned triage program digest was:

```text
sha256:6a281b352c5c7e5dbed6f05336bdabc3c7654f2c7415401eb2a16cf12a6cd7be
```

### Complete managed investigations

| Tenant | Run | Execution | Result |
|---|---|---|---|
| A | `1b1ce7ce-509c-4773-bc0f-28bd3a38dc60` | `0c7a7db9-86da-4b31-b85a-ccd7a8bc660f` | Succeeded; one durable claim, allow audit, completed reservation, connector read, and pinned DSPy evaluation |
| B | `7ae2ba4d-c685-447e-ac43-52935be393a0` | `8aa664e2-a05a-4461-b217-b85ec564aafa` | Succeeded with the same controls in B's independent data plane |

Both requests used `finding-shared`. Tenant A returned
`TENANT-A-CANARY-ONLY`; tenant B returned `TENANT-B-CANARY-ONLY`. Their finding,
prompt, result, trace, queue, database, and reasoning state remained tenant-local.
From both deployed worker pods, the worker PostgreSQL role could count its
`agent_events` ledger but reads of `managed_admissions` and `findings` failed with
PostgreSQL `42501 insufficient_privilege`.

### Workload identity and gateway denial

- The worker reaches the gateway through Envoy using a SPIRE-issued SVID. A fake
  identity header without a client certificate fails at TLS; the application never
  accepts the header as authentication.
- Managed `/internal/tools/invoke` returns 403 to the worker's valid legacy shared
  token. Privileged dispatch succeeds only through the security service.
- Forged-grant run `283c9d5d-2b08-45c1-863c-28ad7817ba07` / execution
  `e1df1aed-10f3-4b11-8712-0410f0197743` altered a signed bound. Authorization
  returned 403, wrote one `grant_invalid` denial audit, created zero reservations,
  and caused zero connector dispatches.
- Re-delivering an already completed run's original signed envelope was denied as
  `claim_state_denied`; a completed admission could not start another execution.

### Lifecycle, approval, replay, and budget

- Cancellation is durable: the admission is revoked, its claim is cancelled, the
  revocation epoch advances, and a separate security-service process denies new
  dispatch after restart.
- Run `a4fe8824-b576-4d01-aff0-5aeb3ddd46b5` exercised two-person approval. The
  requester received 403, a distinct tenant approver succeeded, and an altered
  argument digest received 409.
- A real reasoner outage caused run `31fa350b-1e55-456f-b2a4-38687df16f20` /
  execution `9365cb2d-345d-49bc-8ccc-119f9728b75c` to exhaust its
  three queue attempts. API resume reissued a signed `reason=resume` envelope,
  enqueued idempotently, created claim version 4, preserved the workflow and program
  digests, and completed after recovery.
- Budget/takeover run `2d1604b6-54c5-4a44-bab1-be0a3cf73933` / execution
  `cf459c20-ca4a-430a-ae36-b56a6ffb78cc` claimed twice. The second claim fenced the
  first grant. Two concurrent calls raced for one remaining unit: one succeeded and
  one returned 403. A true retry returned the recorded result; conflicting content
  under the same invocation ID returned 403. Durable state ended with zero units,
  one completed reservation, one allow audit, and two deny audits.
- The program-registry migration installs a PostgreSQL transition guard in both
  tenant databases. A disposable program could move from `approved` to `revoked`;
  its attempted `revoked` to `active` transition and tombstone deletion were both
  rejected with SQLSTATE `23514`, and the source and Helm migration copies matched
  byte-for-byte.

### Network and cloud-state isolation

`infra/phase2-lab/scripts/test.sh` checked ready EndpointSlices before every matrix
and required working positive controls. It passed with exit code 0:

- 12 allowed controls: each worker to its own Redis, restricted ledger, gateway,
  and reasoner; each connector to its tenant-local LocalStack; each reasoner to its
  tenant-local synthetic model endpoint.
- 24 policy drops after successful DNS: each worker to its own connector, backend,
  LocalStack, and model endpoint, plus both directions for every A/B queue,
  database, gateway, reasoner, connector, backend, LocalStack, and model endpoint.
- Tenant-local secret and bucket counts were unchanged after every denied request.
  DNS failure, missing EndpointSlices, unavailable services, and connection refusal
  are errors; only the explicit timeout exit used for a Cilium drop passes.

## Automated validation

```text
Python managed/auth/router/security selection
57 passed, 12 warnings

Helm managed-migration bundle ratchet
5 passed

TypeScript full suite with isolated PostgreSQL test database
75 files passed; 1160 tests passed

TypeScript typecheck and build
passed

Go qualification infrastructure
go test ./... passed (package compiles; no Go unit files)

Pulumi
fresh file:// backend preview passed; 22 local Kubernetes resources to create;
kubeconfig secret-marked; no cloud provider or real AWS resource

Helm
lint passed; A/B managed values rendered; 43 SQL files exist in sorted order;
41_managed_execution.sql and 42_managed_workload_identity.sql rendered

Contracts
JSON Schema, filesystem Postman collection, and OpenAPI 3.1 YAML parsed;
10 Postman requests include positive and managed-denial assertions
```

Postman CLI cannot run collections on this host: it aborts before parsing with
`SecItemCopyMatching failed -50` and exit 139. The filesystem artifacts and local
contract assertions pass, but this environment failure is not recorded as a
Postman execution pass.

A repository-wide Python collection was also attempted with the root lock. It
stopped before executing tests because the independent Medic suites import optional
`re2` and `openapi_spec_validator` packages that are absent from that lock. This is
recorded as an unexecuted whole-repository suite, not as a Phase 2 test pass.

## What remains open

This phase does not make the service ready for live customers by itself.

- kind namespaces and nodes share one developer host and kernel. The test does not
  qualify VM, node, hypervisor, container-escape, or production CNI isolation.
- LocalStack uses synthetic credentials. It does not qualify AWS IAM, KMS, VPC
  endpoints, CloudTrail, regional failure, service quotas, or account boundaries.
- The model endpoint in the network test is synthetic. Deterministic DSPy fixtures
  establish contract and grounding behavior; model quality requires the separately
  invoked, credential-referenced, spend-capped live evaluation.
- T09 central-lease expiry during a real management-plane partition is not run
  because the management plane and central lease issuer are Phase 3 work.
- Backup/restore, upgrade/rollback, disaster recovery, offboarding, operator JIT
  access, production observability isolation, customer provisioning, and all other
  Phase 3 T01-T17 scenarios remain unpassed.

The next phase may build automated dedicated-customer provisioning and operational
qualification on this security contract. It must not weaken the tenant-local
gateway, workload identity, exact-work envelope, program pin, or connector egress
boundaries established here.
