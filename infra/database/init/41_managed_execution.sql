-- Phase 2 managed execution authority. The API owns these records; workers
-- receive signed, bounded envelopes and never need direct access to them.

CREATE TABLE IF NOT EXISTS managed_deployments (
    deployment_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    incarnation UUID NOT NULL,
    policy_version TEXT NOT NULL,
    revocation_epoch BIGINT NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
    authority_public_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'offboarded')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_deployment_tenant ON managed_deployments (tenant_id);

CREATE TABLE IF NOT EXISTS managed_memberships (
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    roles JSONB NOT NULL DEFAULT '[]'::jsonb,
    membership_version BIGINT NOT NULL DEFAULT 1 CHECK (membership_version > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    PRIMARY KEY (tenant_id, subject_id, issuer)
);

CREATE TABLE IF NOT EXISTS managed_admissions (
    admission_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES managed_deployments(deployment_id),
    subject_id TEXT NOT NULL,
    execution_id UUID NOT NULL UNIQUE,
    workflow_id TEXT NOT NULL,
    workflow_digest TEXT NOT NULL,
    program_id TEXT NOT NULL,
    program_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    revocation_epoch BIGINT NOT NULL CHECK (revocation_epoch >= 0),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired'))
);

CREATE TABLE IF NOT EXISTS managed_runs (
    run_id UUID PRIMARY KEY,
    execution_id UUID NOT NULL UNIQUE REFERENCES managed_admissions(execution_id),
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    run_kind TEXT NOT NULL,
    workflow_id TEXT NOT NULL,
    status TEXT NOT NULL,
    request JSONB NOT NULL,
    envelope JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS managed_execution_claims (
    execution_id UUID PRIMARY KEY REFERENCES managed_admissions(execution_id),
    worker_key_id TEXT NOT NULL,
    claim_token TEXT NOT NULL,
    claim_version BIGINT NOT NULL DEFAULT 1 CHECK (claim_version > 0),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claim_until TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'fenced', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS managed_approvals (
    approval_id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES managed_admissions(execution_id),
    approver_subject_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    argument_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('approved', 'expired', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS managed_invocation_reservations (
    invocation_id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES managed_admissions(execution_id),
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    argument_digest TEXT NOT NULL,
    reserved_units INTEGER NOT NULL CHECK (reserved_units > 0),
    outcome JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS managed_authorization_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    execution_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason_code TEXT NOT NULL,
    argument_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS managed_outbox (
    outbox_id BIGSERIAL PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_agent') THEN
    CREATE ROLE vigil_agent NOSUPERUSER LOGIN;
  END IF;
END
$$;

ALTER ROLE vigil_agent NOSUPERUSER LOGIN;
REVOKE ALL ON managed_deployments, managed_memberships, managed_admissions,
  managed_runs, managed_execution_claims, managed_approvals, managed_invocation_reservations,
  managed_authorization_audit, managed_outbox FROM vigil_agent;
GRANT SELECT, INSERT ON agent_events, agent_run_leases TO vigil_agent;
GRANT UPDATE (owner, claim_until) ON agent_run_leases TO vigil_agent;
