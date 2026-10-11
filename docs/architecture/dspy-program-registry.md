# DSPy program registry and reasoning interface

Decision D05: DSPy is the preferred programmable reasoning/optimization layer in each
tenant data plane. No DSPy dependency or production DSPy path was found in the audited
Python requirements or agent source. This is an integration design, not an assertion
that upstream already uses DSPy.

## Program identity and registry records

| Record | Required fields / ownership |
|---|---|
| Program | Globally unique ID, publisher, scope (`global` or one tenant), input/output schema version |
| Immutable version | Semantic version, artifact digest/signature, source commit, dependency/runtime lock, DSPy version, model/provider requirements, data lineage classification |
| Evaluation dataset | Tenant/deployment ownership, local object ref, content digest, consent/use purpose, sensitivity, retention, split manifest and access policy |
| Evaluation result | Program/model/dataset digests, metric definition/version, seed/config, test split, scores, failures, safety/budget results, local trace refs |
| Approval | Reviewer identities, permitted tenant/deployment/environment, policy version, constraints and timestamp; separate optimizer and promotion roles |
| Deployment binding | Tenant/deployment, pinned program/version/digest, provider/model config ref, approval ref, active/previous version, rollout generation |
| Revocation | Program or signer digest, reason, epoch, affected deployments and replacement policy |

Global programs must use public, synthetic or explicitly approved redistributable data.
Tenant variants are inaccessible to other tenants; namespace and ACL checks apply to
listing, download, evaluation results and promotion, not just artifact fetch. Customer
dataset references are not centrally resolvable credentials or URLs. A central registry
can hold a tenant artifact digest/approval receipt without holding its sensitive bytes.

## Lifecycle

`draft → evaluated → reviewed → approved → staged → active → superseded/revoked`.
An optimizer emits a **candidate**, never a production release. Evaluation and policy
gates run locally on pinned train/dev/held-out splits. Record correctness, evidence
grounding, false-positive/negative behavior, refusal/approval compliance, injection
resistance, tool proposal validity, latency and token/cost budgets. Product owners set
use-case thresholds before evaluation; selecting thresholds after viewing held-out
results is not an independent test. Repeated tuning requires a fresh holdout strategy.

Approval is scope-specific. Production admission resolves an exact approved digest;
there is no `latest` or silent fallback to a different program/model. Pin the version
for the entire execution, including retries/resume. Promotion changes only selected
deployments, canaries first; rollback selects a previously approved compatible digest.
Emergency revocation blocks new executions/calls using the revoked artifact; active
executions checkpoint or cancel under local policy. Rollback cannot lower revocation
epochs or revive revoked approvals.

## Reasoner boundary

`Reasoner.evaluate` accepts verified execution identity, program binding, typed inputs,
tenant-local context references, deadline and budget. It returns typed hypotheses,
evidence references, confidence/limitations, proposed actions and usage. Trusted harness
checks response schema and invokes gateway only after independent authorization. Use
a Python DSPy sidecar/process per tenant behind this versioned boundary; retain the
existing TypeScript workflow/ledger through an adapter instead of immediately rewriting
the domain runtime. If DSPy uses tools iteratively, its tool adapter routes through the
same gateway, with no direct integration credential or unrestricted network path.

Local evaluation and optimizer jobs use dedicated workload identities and budgets with
response actions disabled by default. Their privilege is to evaluate approved examples,
not to execute customer containment actions. Customer-specific model config and provider
credentials resolve locally; outbound examples need explicit egress approval.

## Data and artifact safety

Optimized prompts and few-shot demonstrations can contain tenant data even if named
"program artifacts". Classify derived artifacts at least as sensitively as their
inputs. Do not export them to the global registry by default. Tenant mixing requires
an explicit lawful/contractual basis, recorded scope/purpose/approval, and appropriate
data governance; anonymization alone is not assumed sufficient.

Prefer reviewed code packaged in a signed image plus validated declarative program
state. DSPy supports saving state and whole programs; treat executable serialization
as code, never deserialize an untrusted uploaded artifact in a shared process.
[DSPy save/load documentation](https://dspy.ai/current/tutorials/saving/).
Pin runtime dependencies and verify bytes before loading. Approved artifacts must pass
data-leak scans and ownership checks; a global signer does not declassify customer data.

Isolate DSPy caches, LM histories, example stores, embeddings, retrieval clients,
provider sessions and tracing per tenant/deployment; reset execution-local state on
completion. Do not use mutable global model settings to multiplex tenant credentials.
Detailed optimization/evaluation logs stay local in BYOC. The control plane may receive
only approved aggregate scores and artifact metadata. Deletion policies cover examples,
traces, checkpoints, optimized artifacts, model caches and backups, including derived
copies. Tests T03/T13/T15/T16 are release gates.
