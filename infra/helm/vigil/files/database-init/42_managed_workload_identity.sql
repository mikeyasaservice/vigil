-- Durable workload identity and authorization state for the managed gateway.
-- Existing claims were created from caller-controlled fingerprints and are
-- fenced during this migration; workers must reclaim through the SPIFFE proxy.

ALTER TABLE managed_admissions
  ADD COLUMN IF NOT EXISTS issuer TEXT,
  ADD COLUMN IF NOT EXISTS membership_version BIGINT,
  ADD COLUMN IF NOT EXISTS policy_version TEXT;

UPDATE managed_admissions a
SET issuer = m.issuer,
    membership_version = m.membership_version,
    policy_version = d.policy_version
FROM managed_memberships m, managed_deployments d
WHERE a.tenant_id = m.tenant_id
  AND a.subject_id = m.subject_id
  AND a.deployment_id = d.deployment_id
  AND (a.issuer IS NULL OR a.membership_version IS NULL OR a.policy_version IS NULL);

ALTER TABLE managed_execution_claims
  ADD COLUMN IF NOT EXISTS workload_spiffe_id TEXT,
  ADD COLUMN IF NOT EXISTS capabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE managed_execution_claims
SET status = 'fenced'
WHERE status = 'active' AND workload_spiffe_id IS NULL;

CREATE TABLE IF NOT EXISTS managed_execution_budgets (
    execution_id UUID PRIMARY KEY REFERENCES managed_admissions(execution_id),
    remaining_units BIGINT NOT NULL CHECK (remaining_units >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_managed_active_claim
  ON managed_execution_claims (execution_id, workload_spiffe_id, claim_token)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS managed_program_registry (
    tenant_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    program_digest TEXT NOT NULL,
    artifact_signature TEXT NOT NULL,
    model_config_digest TEXT NOT NULL,
    dependency_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('approved', 'active', 'revoked')),
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, program_id, program_digest),
    CHECK ((status = 'active' AND activated_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'approved' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_program_one_active
  ON managed_program_registry (tenant_id, program_id) WHERE status = 'active';

CREATE OR REPLACE FUNCTION managed_program_registry_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status = 'revoked' THEN
      RAISE EXCEPTION 'revoked managed program tombstone cannot be deleted'
        USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.tenant_id <> NEW.tenant_id
     OR OLD.program_id <> NEW.program_id
     OR OLD.program_digest <> NEW.program_digest THEN
    RAISE EXCEPTION 'managed program identity is immutable'
      USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'revoked managed program cannot be reactivated'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS managed_program_registry_guard_update
  ON managed_program_registry;
DROP TRIGGER IF EXISTS managed_program_registry_guard_mutation
  ON managed_program_registry;
CREATE TRIGGER managed_program_registry_guard_mutation
BEFORE UPDATE OR DELETE ON managed_program_registry
FOR EACH ROW EXECUTE FUNCTION managed_program_registry_guard();

CREATE TABLE IF NOT EXISTS managed_integration_bindings (
    binding_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    endpoint_ref TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    UNIQUE (tenant_id, integration_id, tool_name)
);

CREATE TABLE IF NOT EXISTS managed_approval_requests (
    execution_id UUID NOT NULL REFERENCES managed_admissions(execution_id),
    checkpoint_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    argument_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    PRIMARY KEY (execution_id, checkpoint_id)
);

ALTER TABLE managed_approvals
  ADD COLUMN IF NOT EXISTS checkpoint_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_approval_checkpoint
  ON managed_approvals (execution_id, checkpoint_id)
  WHERE checkpoint_id IS NOT NULL AND status = 'approved';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_security') THEN
    CREATE ROLE vigil_security NOSUPERUSER LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_connector') THEN
    CREATE ROLE vigil_connector NOSUPERUSER LOGIN;
  END IF;
END
$$;

ALTER ROLE vigil_security NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN;
ALTER ROLE vigil_connector NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN;

GRANT SELECT, INSERT, UPDATE ON managed_execution_claims,
  managed_invocation_reservations, managed_authorization_audit,
  managed_approval_requests TO vigil_security;
GRANT SELECT ON managed_admissions, managed_runs, managed_deployments,
  managed_memberships, managed_approvals, managed_execution_budgets,
  managed_program_registry, managed_integration_bindings TO vigil_security;
GRANT UPDATE (remaining_units, updated_at) ON managed_execution_budgets TO vigil_security;
GRANT UPDATE (status, updated_at) ON managed_runs TO vigil_security;
GRANT USAGE, SELECT ON SEQUENCE managed_authorization_audit_audit_id_seq TO vigil_security;

-- Domain tables are created later by SQLAlchemy on fresh installations. The
-- Helm managed-role reconciliation job waits for those exact tables and grants
-- their narrowly scoped read privileges. Keeping that step outside this file
-- prevents a missing table from being hidden by the legacy migration runner.

REVOKE ALL ON managed_deployments, managed_memberships, managed_admissions,
  managed_runs, managed_execution_claims, managed_approvals,
  managed_invocation_reservations, managed_authorization_audit, managed_outbox,
  managed_execution_budgets, managed_program_registry,
  managed_integration_bindings, managed_approval_requests FROM vigil_connector;

REVOKE ALL ON managed_execution_budgets FROM vigil_agent;
REVOKE ALL ON managed_program_registry FROM vigil_agent;
REVOKE ALL ON managed_integration_bindings FROM vigil_agent;
