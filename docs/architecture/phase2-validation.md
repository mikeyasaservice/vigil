# Phase 2 secure execution foundation

Status: **remediation implemented; managed profile remains blocked from readiness**.
Branch: `codex/phase2-secure-execution`.

The branch now enforces the first security slice: exact grant/execution binding,
positive and idempotent budget reservations, job/request binding, fail-closed
managed resumes, a gateway-owned dispatch route, durable run/outbox records, and
artifact-derived DSPy pinning. The deployed application path and full T01–T13
isolation evidence are still outstanding; this document does not claim production
readiness.

## Evidence recorded on this branch

| Area | Evidence | Result |
|---|---|---|
| Contracts | `contracts/managed-execution.schema.json`, `contracts/managed-agent-runs.openapi.yaml` | JSON schema parses; OpenAPI is committed for local Postman validation |
| Identity and queue | `core/agents/managed_execution.py`, `core/api/v2/agent_runs_router.py`, signed queue envelope tests | Exact execution/grant binding, tamper, foreign worker, cancellation and replay-conflict cases pass; deployed claim/revocation remains pending |
| Connector bindings | `core/agents/managed_bindings.py` | Tenant ownership and endpoint allowlist refusals pass |
| Tool boundary | `core/agents/managed_gateway_router.py`, `services/agent/core/managed-gateway.ts`, managed `remoteDispatch` path | Managed workers dispatch through the independent gateway; direct legacy-token calls are refused; deployed mTLS and connector sink evidence remains pending |
| Reasoner | `services/reasoner/programs/triage_v1.py`, `services/reasoner/app.py` | Deterministic fixture validates evidence references and proposal-only actions |
| Database boundary | `infra/database/init/41_managed_execution.sql`, `core/agents/managed_store.py` | Managed runs, admissions, claims, approvals, reservations, audit and outbox tables plus API repository are declared; authority claim persistence still needs deployment verification |
| Packaging | Helm `.helmignore`, managed deny-egress values/template | `helm lint` and managed template rendering pass |
| Lab infrastructure | `infra/phase2-lab` | Pulumi Go program compiles and unit command passes |
| Deployed lab | `kind-vigil-phase2`, Cilium 1.20.1, LocalStack 4.8.1 | Namespace/policy slice completed; application worker, gateway, connector, positive controls and counter-based denial probes are not yet rerun |

## Commands and results

```text
uv run --offline --with pydantic-settings --with pytest --with pytest-asyncio --with pytest-cov --with cryptography --with fastapi --with sqlalchemy --with pydantic python3 -m pytest -q tests/unit/agents/test_managed_execution.py tests/unit/agents/test_managed_bindings.py tests/unit/agents/test_reasoner_contract.py
9 passed

cd services/agent && npm run typecheck
passed

cd services/agent && npm exec -- vitest run tests/core/managed.test.ts tests/core/remote.test.ts tests/core/lead.test.ts tests/core/harness.test.ts
45 tests passed

helm lint infra/helm/vigil
1 chart(s) linted, 0 failed

helm template phase2 infra/helm/vigil --set networkPolicies.enabled=true --set networkPolicies.managedExecution=true
rendered

cd infra/phase2-lab && go test ./...
passed (no Go test files; package compiles)

./scripts/provision.sh; ./scripts/seed.sh; Pulumi preview/up
Cilium healthy on 3/3 nodes; LocalStack S3/Secrets Manager healthy; Pulumi 6 resources created

The previous network-only probe is historical evidence only. It did not provide a
working same-tenant control and therefore cannot establish application isolation.
```

The existing worker integration suite was also attempted. Its database-backed cases
were blocked in this sandbox by `EPERM` when connecting to the local Postgres port;
that is environment evidence, not an authorization pass.

## Limitations and next checkpoint

The API repository now persists managed run and outbox records, but the authority's
claim, grant, revocation and reservation adapter still needs to use the same durable
trusted state across service processes. The Pulumi program declares the disposable
namespaces and deny policies; it does not create or alter the existing `kind-kind`
cluster.

Postman CLI spec lint was unavailable because its macOS keychain lookup failed before
parsing the document. The deployed probe covers only the lab network-policy slice; it
does not pass the full T01–T13 production gates. The next checkpoint is durable
admission persistence, explicit allow-egress policies for required worker endpoints,
and deployed application worker/connector probes.
