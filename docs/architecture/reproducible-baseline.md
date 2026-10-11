# Reproducible Phase 1 baseline

Source: `https://github.com/mikeyasaservice/vigil`.
Commit: `0226200c476913b8bd5dff1df9bb221c6b147186`.
Git tree: `47da2ec975b062aa78144cebb71206ce87c3048f`.
Audit date: 2026-10-11. Upstream source/runtime code was not modified for this audit.
Source and dependency-file hashes are in [baseline.json](evidence/baseline.json).

## Reproduce the source baseline

```sh
git clone https://github.com/mikeyasaservice/vigil.git vigil-phase1
cd vigil-phase1
git checkout --detach 0226200c476913b8bd5dff1df9bb221c6b147186
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
```

The Phase 1 documents/script are additions to that commit. In a checkout containing
these additions and unmodified audited source:

```sh
python3 scripts/architecture/collect_phase1_baseline.py
python3 scripts/architecture/collect_phase1_baseline.py --check
```

Collector requires only Python standard library and Git, refuses modified audited
source (documentation-only commits may advance HEAD), and never imports Vigil. It recorded **55 tables, zero tenant
columns, and 382 route declarations**. Route decorators are not a complete mounted
route inventory; no authorization classification is inferred from syntax alone.

`.python-version` specifies Python 3.12. `requirements.lock` pins Python packages but
does not carry artifact hashes; immutable package mirrors/hash verification remain a
supply-chain reproducibility improvement. Agent/frontend package-lock files and Helm
Chart.lock are preserved. Agent package supports Node ≥20; exact runtime toolchain and
container digests must be pinned for production releases. Never deploy mutable image
tags merely because source/dependency versions were pinned.

## Validation actually performed

| Check | Result | Scope / limitation |
|---|---|---|
| Agent `npm ci --ignore-scripts --no-audit --no-fund` | PASS, 127 packages installed from lock | Dependency lifecycle scripts disabled; no lock changes |
| `npm run typecheck` in `services/agent` | PASS | TypeScript static check |
| `npm run test:unit` | 63 files passed; 1 failed due sandbox socket denial. 1,022 passed / 22 failed out of 1,044 | HTTP server could not listen on 127.0.0.1 (`EPERM`); failures were environment-dependent |
| Targeted `npm exec -- vitest run tests/chat/serve.test.ts` with localhost access | PASS: 29/29 | Re-ran the entire affected file; seven had already passed. Together all 1,044 unique unit cases passed across the two runs; no single clean full-suite run claimed |
| Python internal-auth and route-auth tests | PASS: 10/10 in temporary Python 3.12.14 environment synced from `requirements.lock` (134 packages) | Initial host-Python attempt failed before collection; isolated locked environment resolved it. Tests check internal token behavior and mounted route auth coverage, not tenant isolation |
| Helm locked dependency build | PASS after configuring temporary repository entries | No user Helm repo config changed; downloaded artifacts remain local/ignored |
| Unmodified chart render, Helm 4.3.0 | FAIL | `.helmignore` contains `*.tgz`, excluding downloaded dependencies from render loader despite dependency list reporting OK |
| Temporary chart copy, removing only `*.tgz` ignore line | PASS for `audit-a`/`audit-b` in distinct namespaces | 26 resources and 8 NetworkPolicies each, zero overlapping resource identities; includes allow-all egress. No cluster install or isolation proof |
| Static baseline regeneration/check | PASS | Deterministic source-only inventory/hashes |
| New documentation and collector checks | PASS | All 16 required docs, 58 relative links across 24 Markdown files, JSON syntax, complete 55-table grouping, gate references, Python compilation and pinned Black/isort formatting |
| Live PostgreSQL/Redis, full backend, Docker smoke, cloud IAM/CNI, restore/PITR and mandatory T01–T17 | NOT RUN | No test infrastructure provisioned; Docker socket inaccessible in sandbox; proposed managed runtime not implemented |

Observed shell tools: Node 20.19.5, Helm 4.3.0, Python 3.14.7, Docker client 28.5.1;
locked Python validation used CPython 3.12.14 in an isolated temporary environment.
Vitest resolved to 4.1.11 from the lock. Helm packaging failure is verified for this
toolchain; supported Helm 3 behavior remains to be qualified before changing upstream.
No customer secrets, telemetry, live integrations or cloud accounts were used.
Python tests emitted an upstream SQLAlchemy `noload()` deprecation warning and a
duplicate Bifrost proxy OpenAPI operation-ID warning; neither failed the selected tests.

## Reproduce Python authentication checks

```sh
audit_python_dir="$(mktemp -d)"
uv venv --python 3.12 "$audit_python_dir/venv"
uv pip sync --python "$audit_python_dir/venv/bin/python" requirements.lock
VIGIL_DIR="$audit_python_dir/state" VIGIL_DISABLE_DOTENV=1 \
  JWT_SECRET_KEY=phase1-test-only-not-for-production \
  "$audit_python_dir/venv/bin/python" -m pytest -q -o addopts='' \
  tests/unit/agents/test_internal_auth.py tests/security/test_route_auth_coverage.py
```

The tests force authentication on and prevent ambient database access through their
fixtures. The command disables the suite-wide coverage report for this focused run;
it does not disable authentication or alter test cases. Runtime dependencies come
from the checked-in lock, not the host's Python installation.

## Reproduce agent checks

```sh
cd services/agent
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run test:unit
```

The test process needs permission to open a loopback server. These unit tests use
fixtures/fakes; they do not verify PostgreSQL, Redis, cross-tenant policy or cloud IAM.
For the targeted environment-related rerun:

```sh
npm exec -- vitest run tests/chat/serve.test.ts
```

## Reproduce Helm experiment without deployment

Use a temporary repository configuration/cache so the audit does not change the
operator's global Helm settings. Commands fetch chart dependencies, not cloud resources.

```sh
audit_helm_dir="$(mktemp -d)"
helm repo add phase1-otel https://open-telemetry.github.io/opentelemetry-helm-charts \
  --repository-config "$audit_helm_dir/repositories.yaml" --repository-cache "$audit_helm_dir/cache"
helm repo add phase1-bitnami https://charts.bitnami.com/bitnami \
  --repository-config "$audit_helm_dir/repositories.yaml" --repository-cache "$audit_helm_dir/cache"
helm dependency build infra/helm/vigil \
  --repository-config "$audit_helm_dir/repositories.yaml" --repository-cache "$audit_helm_dir/cache"
helm template audit-a infra/helm/vigil --namespace audit-a \
  --set secrets.postgresPassword=phase1-test-only \
  --set secrets.jwtSecretKey=phase1-test-only-not-for-production \
  --set secrets.agentInternalToken=phase1-test-only \
  --set networkPolicies.enabled=true
```

The last command failed as recorded above. For the separate diagnostic experiment,
copy the whole chart (including downloaded `charts/`) into a temporary directory,
remove only the exact `*.tgz` line from its `.helmignore`, and render the copy for
`audit-a` and `audit-b` namespaces with the same synthetic values. The source chart was
not changed. These literal credentials are test-only examples and must never be used
in a running deployment. Distinct names show parameterization, not network isolation.

## Complete runtime qualification later

Use an isolated lab with synthetic credentials, private state directory, test database
and broker; do not point tests at a developer/customer instance. Provision the pinned
Python 3.12 environment with `uv` and `requirements.lock`, then run the existing
internal-auth, route-auth, backend integration, agent integration and backup/restore
suites using their test-service fixtures. Record exact interpreter, container digests,
DB roles, env profile and test outputs in a new validation report.

Explicitly disable auth bypass, enforce revocation failure closure, verify trusted
proxy/CSRF settings and keep integrations unconfigured until synthetic sinks are ready.
Qualify the complete start/schema/migration/seed sequence and two concurrent isolated
installations. Capture effective PostgreSQL grants/RLS and broker/CNI policies from the
running system. The present source baseline is reproducible; a fully reproducible,
running managed-service deployment remains a Phase 2/3 exit requirement.

## Architecture consistency walkthrough

| Scenario | Design resolution | Runtime proof still required |
|---|---|---|
| A supplies B tenant on a run | Server membership + deployment binding; signed job context; consumer revalidation | T04/T05 |
| Worker skips its registry | Gateway independently verifies workload-bound scoped grant; direct integration egress denied | T02/T06 |
| Shared DB runtime sets tenant variable | No shared rows in MVP; future DB design rejects arbitrary session variable as authority | T14 |
| BYOC management unavailable | Local standing authority continues, central authority expires, local emergency controls remain | T09/T10 |
| Valid fleet signer requests unapproved image | Local release/approval policy can reject; distinct release/fleet keys | T08/T13 |
| Restore predates deletion/revocation | Quarantine, current tombstones/deny epoch, new incarnation; otherwise privileged actions remain denied | T11/T16 |

This validates that the written contracts have a defined response to the principal
boundary failures. It is not an independent security review or a passing runtime gate.
