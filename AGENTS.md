# Managed-service architecture constraints

Postman CLI is installed and available for API engineering work.

This fork targets one product in shared SaaS, dedicated managed, and BYOC modes.
Read [the architecture index](docs/architecture/README.md) before changing a trust
boundary, persistence, authentication, agent execution, integrations, or deployment.

- Phase 1 defines contracts and audits upstream; it does not establish production readiness.
- Derive tenant identity from authenticated, authorized server-side context. A request
  field, header, prompt, workspace name, or queue label is never proof of membership.
- Keep customer data and credentials in its data plane. Management access does not
  imply data access or tool privileges.
- Until isolation gates pass, use dedicated tenant application, execution, database,
  queue, secrets, and model-context boundaries. Never switch tenant credentials in
  a shared agent process.
- DSPy selects reasoning behavior; independent trusted infrastructure authorizes
  every privileged tool call. Production programs must be approved and pinned.
- BYOC local security enforcement must survive management disconnection. Fail closed
  for an action whose required authorization cannot be verified locally.
- Every affected change must name its tenant boundary, identity source, secret/data
  flows, failure behavior, and relevant production-readiness test IDs in review.
- Keep upstream domain code and frozen contracts compatible through explicit adapters
  and versioned migrations. No separate customer or deployment-mode product forks.
- Do not mark a gate passed from static inspection, a mock, or an unrelated unit test.
