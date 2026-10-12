# DSPy optimization lifecycle implementation and validation

Date: 2026-10-12. Branch: `codex/production-qualification`.

## Implemented path

```text
authenticated tenant user
  -> server-derived tenant/deployment membership
  -> locked deployment-local dataset reference
  -> budgeted local evaluation / optimizer record
  -> declarative signed candidate
  -> passing holdout + safety evaluations
  -> distinct approver signs exact promotion digest
  -> approved staging without a deployment change
  -> separately approved deployment-scoped activation generation
  -> exact program digest admitted by the managed execution registry
  -> two-person rollback to the exact previous unrevoked digest
```

The schema records datasets, evaluations, optimizer runs, promotions, activation
generations and audit events. Dataset bytes, examples, optimizer demonstrations, traces,
model credentials and candidate bytes remain inside the tenant data plane. The global
management plane may receive only the signed aggregate evaluation receipt defined in
`contracts/dspy-lifecycle.schema.json`.

## Boundary and failure behavior

| Concern | Enforcement | Failure behavior | Readiness tests |
|---|---|---|---|
| Tenant boundary | Membership resolver derives tenant/deployment; every lifecycle query binds both | Foreign dataset, artifact, evaluation or promotion is refused | T03, T05, T13 |
| Dataset lineage | Local reference, content/schema digests, four immutable splits, purpose/sensitivity/retention/access policy | Changed content or identity fails in the database trigger | T03, T13, T16 |
| Optimization | Dedicated reasoner identity, approved base digest, pinned optimizer/config/model/dependency digests, positive token/cost budgets | Missing source or over-budget completion cannot become a candidate | T12, T13 |
| Artifact safety | DSPy state-only JSON; executable pickle/whole-program upload is not accepted | Non-JSON output is rejected before registration | T13 |
| Evaluation | `services.reasoner.evaluate` verifies candidate digest, signature and deployment ownership before loading state; thresholds are fixed at creation; only development/holdout/safety qualify | Malformed, altered, foreign, invented-evidence, unsafe-action or over-budget evaluation fails closed | T03, T12, T13 |
| Promotion | Exact candidate requires passing holdout and safety results; approver differs from requester | Altered, stale, foreign or self-approved request is rejected | T06, T13 |
| Staging/activation/rollback | Staging registers the signed candidate without changing deployment state. Activation and rollback are separate authority-signed, generation-scoped transitions | Revoked candidates cannot stage, activate or return through rollback; stale generation changes roll back atomically | T10, T13 |
| BYOC export | Connector allows a fixed aggregate receipt bound to local tenant/deployment | Examples, prompts, traces and local refs have no export fields; foreign receipts fail | T03, T08, T13, T15 |

## Executed evidence

| Validation | Result | Narrow claim |
|---|---|---|
| Lifecycle/API/security unit suite | 35 passed | Unicode-stable digests, ownership, signed candidate loading, four-way splits, grounding/action checks, aggregate-only receipt, OpenAPI/Postman parity, managed gateway regressions and Helm migration bundle behave as specified. |
| Management/BYOC contract suite | 9 passed | Aggregate receipts are event-kind bound and expose neither customer examples nor traces. |
| Managed router discovery | 14 passed with explicit synthetic trust material | The authenticated lifecycle router mounts in managed mode without path shadowing or import-time database access. |
| Phase 5 Go tests | Passed | The outbound connector accepts a bound aggregate receipt and rejects a foreign receipt or fields on another event kind. |
| DSPy runtime entry points | Passed with `dspy==3.4.0` | Reviewed program plus `MIPROv2`, `BootstrapFewShot`, optimizer CLI and signature-verifying evaluator CLI construct under the pinned reasoner dependency set; no model request was made. |
| PostgreSQL 16 lifecycle integration | 1 passed in a disposable container | Migrations 41–43 applied and the complete dataset→candidate→holdout/safety→stage→activate→two-person rollback path executed; staging left the binding unchanged and a revoked rollback target was denied. |
| OpenAPI 3.1 validation and JSON parsing | Passed | Both lifecycle and management specifications validate; lifecycle schema and local Postman collection parse. |
| Postman CLI lint | Tool exited 139 after macOS `SecItemCopyMatching failed -50` | No lint result is claimed from this CLI run; filesystem parity tests are the current contract evidence. |

## Reproducible commands

```bash
python3 scripts/generate_dspy_postman.py
uv run --with-requirements requirements.txt --with-requirements requirements-dev.txt \
  pytest -q -o addopts='' tests/unit/agents/test_dspy_lifecycle.py \
  tests/unit/api/test_dspy_lifecycle_contract.py \
  tests/unit/_ratchets/test_helm_db_init_sql_files.py
(cd infra/phase5-byoc && go test ./...)
uv run --with-requirements services/reasoner/requirements.txt \
  python -m services.reasoner.optimize --help
uv run --with-requirements services/reasoner/requirements.txt \
  python -m services.reasoner.evaluate --help
```

## Remaining qualification

This is implementation and local validation evidence. It does not establish production
model quality or customer-cloud isolation. Before promoting a real program, run a
budgeted optimizer and evaluator entry points with the selected provider against a
customer-approved local dataset, scan the derived demonstrations for tenant data,
rotate the artifact signer, activate a canary deployment, verify retry and resume remain
pinned, and repeat the aggregate receipt test through a deployed customer-owned BYOC
connector. T03/T13 remain partial until that evidence exists.
