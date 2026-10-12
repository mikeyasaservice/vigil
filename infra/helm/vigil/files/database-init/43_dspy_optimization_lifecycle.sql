-- Tenant-local DSPy dataset, evaluation, optimization and promotion history.
-- Sensitive examples and traces are referenced through deployment-local refs;
-- the management plane may receive only signed aggregate receipts.

CREATE TABLE IF NOT EXISTS managed_dspy_datasets (
    dataset_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES managed_deployments(deployment_id),
    name TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    object_ref TEXT NOT NULL CHECK (object_ref LIKE 'local:%'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^sha256:[a-f0-9]{64}$'),
    schema_digest TEXT NOT NULL CHECK (schema_digest ~ '^sha256:[a-f0-9]{64}$'),
    split_manifest JSONB NOT NULL,
    use_purpose TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('synthetic', 'internal', 'confidential', 'restricted')),
    retention_policy_ref TEXT NOT NULL CHECK (retention_policy_ref LIKE 'local:%'),
    access_policy_ref TEXT NOT NULL CHECK (access_policy_ref LIKE 'local:%'),
    status TEXT NOT NULL DEFAULT 'locked' CHECK (status IN ('locked', 'retired', 'deleted')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    UNIQUE (tenant_id, name, version),
    UNIQUE (tenant_id, dataset_id),
    CHECK (jsonb_typeof(split_manifest) = 'object')
);

CREATE TABLE IF NOT EXISTS managed_dspy_evaluations (
    evaluation_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    dataset_id UUID NOT NULL,
    dataset_digest TEXT NOT NULL CHECK (dataset_digest ~ '^sha256:[a-f0-9]{64}$'),
    program_id TEXT NOT NULL,
    program_digest TEXT NOT NULL CHECK (program_digest ~ '^sha256:[a-f0-9]{64}$'),
    model_config_digest TEXT NOT NULL CHECK (model_config_digest ~ '^sha256:[a-f0-9]{64}$'),
    evaluator_digest TEXT NOT NULL CHECK (evaluator_digest ~ '^sha256:[a-f0-9]{64}$'),
    metric_contract_digest TEXT NOT NULL CHECK (metric_contract_digest ~ '^sha256:[a-f0-9]{64}$'),
    split_name TEXT NOT NULL CHECK (split_name IN ('train', 'development', 'holdout', 'safety')),
    seed BIGINT NOT NULL,
    thresholds JSONB NOT NULL,
    metrics JSONB,
    failures JSONB,
    local_trace_ref TEXT CHECK (local_trace_ref IS NULL OR local_trace_ref LIKE 'local:%'),
    execution_location TEXT NOT NULL CHECK (execution_location IN ('tenant-local', 'byoc-local')),
    max_tokens BIGINT NOT NULL CHECK (max_tokens > 0),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd > 0),
    used_tokens BIGINT CHECK (used_tokens IS NULL OR used_tokens >= 0),
    used_cost_microusd BIGINT CHECK (used_cost_microusd IS NULL OR used_cost_microusd >= 0),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'passed', 'failed', 'cancelled')),
    requested_by TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, dataset_id) REFERENCES managed_dspy_datasets(tenant_id, dataset_id),
    CHECK (jsonb_typeof(thresholds) = 'object'),
    CHECK (metrics IS NULL OR jsonb_typeof(metrics) = 'object'),
    CHECK (failures IS NULL OR jsonb_typeof(failures) = 'array')
);

CREATE TABLE IF NOT EXISTS managed_dspy_optimizations (
    optimization_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    dataset_id UUID NOT NULL,
    dataset_digest TEXT NOT NULL CHECK (dataset_digest ~ '^sha256:[a-f0-9]{64}$'),
    base_program_id TEXT NOT NULL,
    base_program_digest TEXT NOT NULL CHECK (base_program_digest ~ '^sha256:[a-f0-9]{64}$'),
    optimizer_name TEXT NOT NULL CHECK (optimizer_name IN ('bootstrap-few-shot', 'miprov2')),
    optimizer_config JSONB NOT NULL,
    optimizer_config_digest TEXT NOT NULL CHECK (optimizer_config_digest ~ '^sha256:[a-f0-9]{64}$'),
    model_config_digest TEXT NOT NULL CHECK (model_config_digest ~ '^sha256:[a-f0-9]{64}$'),
    dependency_digest TEXT NOT NULL CHECK (dependency_digest ~ '^sha256:[a-f0-9]{64}$'),
    seed BIGINT NOT NULL,
    max_tokens BIGINT NOT NULL CHECK (max_tokens > 0),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd > 0),
    used_tokens BIGINT CHECK (used_tokens IS NULL OR used_tokens >= 0),
    used_cost_microusd BIGINT CHECK (used_cost_microusd IS NULL OR used_cost_microusd >= 0),
    candidate_artifact_ref TEXT CHECK (candidate_artifact_ref IS NULL OR candidate_artifact_ref LIKE 'local:%'),
    candidate_digest TEXT CHECK (candidate_digest IS NULL OR candidate_digest ~ '^sha256:[a-f0-9]{64}$'),
    candidate_signature TEXT,
    lineage_classification TEXT NOT NULL CHECK (lineage_classification IN ('synthetic', 'tenant-derived', 'redistributable')),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'candidate', 'failed', 'cancelled', 'revoked')),
    requested_by TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, dataset_id) REFERENCES managed_dspy_datasets(tenant_id, dataset_id),
    CHECK (jsonb_typeof(optimizer_config) = 'object'),
    CHECK ((status = 'candidate' AND candidate_artifact_ref IS NOT NULL AND candidate_digest IS NOT NULL AND candidate_signature IS NOT NULL)
        OR status <> 'candidate')
);

CREATE TABLE IF NOT EXISTS managed_dspy_promotions (
    promotion_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    optimization_id UUID NOT NULL REFERENCES managed_dspy_optimizations(optimization_id),
    evaluation_id UUID NOT NULL REFERENCES managed_dspy_evaluations(evaluation_id),
    program_id TEXT NOT NULL,
    candidate_digest TEXT NOT NULL CHECK (candidate_digest ~ '^sha256:[a-f0-9]{64}$'),
    target_stage TEXT NOT NULL CHECK (target_stage IN ('staged', 'active')),
    policy_version TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    approval_signature TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'staged', 'rejected', 'activated', 'revoked')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    CHECK (approved_by IS NULL OR approved_by <> requested_by),
    CHECK ((status IN ('approved', 'staged', 'activated') AND approved_by IS NOT NULL AND approval_signature IS NOT NULL)
        OR status NOT IN ('approved', 'staged', 'activated'))
);

CREATE TABLE IF NOT EXISTS managed_dspy_deployment_bindings (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    active_program_digest TEXT NOT NULL CHECK (active_program_digest ~ '^sha256:[a-f0-9]{64}$'),
    previous_program_digest TEXT CHECK (previous_program_digest IS NULL OR previous_program_digest ~ '^sha256:[a-f0-9]{64}$'),
    promotion_id UUID NOT NULL REFERENCES managed_dspy_promotions(promotion_id),
    rollout_generation BIGINT NOT NULL CHECK (rollout_generation > 0),
    activated_by TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, deployment_id, program_id)
);

CREATE TABLE IF NOT EXISTS managed_dspy_rollbacks (
    rollback_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    from_program_digest TEXT NOT NULL CHECK (from_program_digest ~ '^sha256:[a-f0-9]{64}$'),
    target_program_digest TEXT NOT NULL CHECK (target_program_digest ~ '^sha256:[a-f0-9]{64}$'),
    policy_version TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    approval_signature TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'applied', 'rejected', 'revoked')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    CHECK (from_program_digest <> target_program_digest),
    CHECK (approved_by IS NULL OR approved_by <> requested_by),
    CHECK ((status IN ('approved', 'applied') AND approved_by IS NOT NULL AND approval_signature IS NOT NULL)
        OR status NOT IN ('approved', 'applied'))
);

ALTER TABLE managed_dspy_deployment_bindings
  ADD COLUMN IF NOT EXISTS last_rollback_id UUID REFERENCES managed_dspy_rollbacks(rollback_id);

CREATE TABLE IF NOT EXISTS managed_dspy_lifecycle_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    actor_subject_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_managed_dspy_evaluation_history
  ON managed_dspy_evaluations (tenant_id, program_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_managed_dspy_optimization_history
  ON managed_dspy_optimizations (tenant_id, base_program_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_managed_dspy_promotion_history
  ON managed_dspy_promotions (tenant_id, program_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_managed_dspy_rollback_history
  ON managed_dspy_rollbacks (tenant_id, program_id, requested_at DESC);

CREATE OR REPLACE FUNCTION managed_dspy_dataset_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.deployment_id <> NEW.deployment_id
     OR OLD.dataset_id <> NEW.dataset_id OR OLD.content_digest <> NEW.content_digest
     OR OLD.schema_digest <> NEW.schema_digest OR OLD.object_ref <> NEW.object_ref
     OR OLD.split_manifest <> NEW.split_manifest THEN
    RAISE EXCEPTION 'locked DSPy dataset identity and content are immutable' USING ERRCODE = '23514';
  END IF;
  IF OLD.status IN ('retired', 'deleted') AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'retired or deleted DSPy dataset cannot be restored' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS managed_dspy_dataset_guard_mutation ON managed_dspy_datasets;
CREATE TRIGGER managed_dspy_dataset_guard_mutation
BEFORE UPDATE ON managed_dspy_datasets
FOR EACH ROW EXECUTE FUNCTION managed_dspy_dataset_guard();

CREATE OR REPLACE FUNCTION managed_dspy_candidate_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.tenant_id <> NEW.tenant_id OR OLD.optimization_id <> NEW.optimization_id
     OR (OLD.candidate_digest IS NOT NULL AND OLD.candidate_digest IS DISTINCT FROM NEW.candidate_digest)
     OR (OLD.candidate_artifact_ref IS NOT NULL AND OLD.candidate_artifact_ref IS DISTINCT FROM NEW.candidate_artifact_ref) THEN
    RAISE EXCEPTION 'DSPy candidate identity and artifact are immutable' USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'revoked DSPy candidate cannot be restored' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS managed_dspy_candidate_guard_mutation ON managed_dspy_optimizations;
CREATE TRIGGER managed_dspy_candidate_guard_mutation
BEFORE UPDATE ON managed_dspy_optimizations
FOR EACH ROW EXECUTE FUNCTION managed_dspy_candidate_guard();

ALTER TABLE managed_program_registry
  ADD COLUMN IF NOT EXISTS source_optimization_id UUID,
  ADD COLUMN IF NOT EXISTS source_evaluation_id UUID,
  ADD COLUMN IF NOT EXISTS artifact_ref TEXT,
  ADD COLUMN IF NOT EXISTS semantic_version TEXT,
  ADD COLUMN IF NOT EXISTS lineage_classification TEXT;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_reasoner') THEN
    CREATE ROLE vigil_reasoner NOSUPERUSER LOGIN;
  END IF;
END $$;

ALTER ROLE vigil_reasoner NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN;
REVOKE ALL ON managed_dspy_datasets, managed_dspy_evaluations,
  managed_dspy_optimizations, managed_dspy_promotions,
  managed_dspy_deployment_bindings, managed_dspy_rollbacks,
  managed_dspy_lifecycle_audit, managed_program_registry FROM vigil_reasoner;
REVOKE ALL ON SEQUENCE managed_dspy_lifecycle_audit_audit_id_seq FROM vigil_reasoner;
GRANT SELECT ON managed_dspy_datasets, managed_dspy_evaluations,
  managed_dspy_optimizations, managed_program_registry TO vigil_reasoner;

GRANT SELECT, INSERT, UPDATE ON managed_dspy_datasets, managed_dspy_evaluations,
  managed_dspy_optimizations, managed_dspy_promotions, managed_dspy_deployment_bindings,
  managed_dspy_rollbacks, managed_dspy_lifecycle_audit TO vigil_security;
GRANT USAGE, SELECT ON SEQUENCE managed_dspy_lifecycle_audit_audit_id_seq TO vigil_security;

REVOKE ALL ON managed_dspy_datasets, managed_dspy_evaluations,
  managed_dspy_optimizations, managed_dspy_promotions, managed_dspy_deployment_bindings,
  managed_dspy_rollbacks, managed_dspy_lifecycle_audit FROM vigil_agent, vigil_connector;
