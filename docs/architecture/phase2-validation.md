# Phase 2 secure execution foundation

Status: **implementation slice complete; local security gates partially run**.
Branch: `codex/phase2-secure-execution`.

This phase implements the first managed path: an authenticated API resolves a
server-side membership, creates a signed admission envelope, enqueues bounded
references, and requires a worker execution claim before the TypeScript harness can
dispatch a privileged tool. The reasoner returns typed proposals; the capability
gateway remains the authority for side effects.

## Evidence recorded on this branch

| Area | Evidence | Result |
|---|---|---|
| Contracts | `contracts/managed-execution.schema.json`, `contracts/managed-agent-runs.openapi.yaml` | JSON schema parses; OpenAPI is committed for local Postman validation |
| Identity and queue | `core/agents/managed_execution.py`, `core/api/v2/agent_runs_router.py`, signed queue envelope tests | Valid admission, tamper, foreign worker, revocation and replay-conflict cases pass |
| Connector bindings | `core/agents/managed_bindings.py` | Tenant ownership and endpoint allowlist refusals pass |
| Tool boundary | `services/agent/core/managed-gateway.ts`, managed `remoteDispatch` path | Managed local I/O is refused; authorizer is required before dispatch |
| Reasoner | `services/reasoner/programs/triage_v1.py`, `services/reasoner/app.py` | Deterministic fixture validates evidence references and proposal-only actions |
| Database boundary | `infra/database/init/41_managed_execution.sql` | Security tables and restricted worker grants are declared |
| Packaging | Helm `.helmignore`, managed deny-egress values/template | `helm lint` and managed template rendering pass |
| Lab infrastructure | `infra/phase2-lab` | Pulumi Go program compiles and unit command passes |

## Commands and results

```text
python -m pytest -q -o addopts='' tests/unit/agents/test_managed_execution.py tests/unit/agents/test_reasoner_contract.py
6 passed

cd services/agent && npm run typecheck
passed

cd services/agent && npm exec -- vitest run tests/core/remote.test.ts tests/core/contracts.test.ts
27 tests passed

helm lint infra/helm/vigil
1 chart(s) linted, 0 failed

helm template phase2 infra/helm/vigil --set networkPolicies.enabled=true --set networkPolicies.managedExecution=true
rendered

cd infra/phase2-lab && go test ./...
passed
```

## Limitations and next checkpoint

The API adapter currently keeps its authority and run index in process memory while
the versioned SQL schema is introduced. A production deployment must move admission,
revocation, claims, budgets and audit reservations to that trusted store before the
managed profile is enabled. The Pulumi program declares the disposable namespaces and
deny policies; it does not create or alter the existing `kind-kind` cluster.

The disposable kind/Cilium/LocalStack lab was not run in this environment because the
Docker socket was unavailable. Postman CLI spec lint was also unavailable because its
macOS keychain lookup failed before parsing the document. These are unrun evidence,
not passing isolation gates. The next checkpoint is durable admission persistence,
explicit allow-egress policies for the required endpoints, then deployed worker-pod
connectivity and cross-tenant negative probes T01–T13.
