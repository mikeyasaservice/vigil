BEGIN;

CREATE TABLE IF NOT EXISTS management_tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
      CHECK (status IN ('active', 'suspended', 'offboarding', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_operator_scopes (
    scope_id BIGSERIAL PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    tenant_id TEXT REFERENCES management_tenants(tenant_id),
    role TEXT NOT NULL CHECK (role IN ('platform_admin', 'deployment_operator', 'deployment_approver', 'auditor')),
    membership_version BIGINT NOT NULL CHECK (membership_version > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_management_operator_scope_identity
  ON management_operator_scopes (issuer, subject_id, COALESCE(tenant_id, '*'), role);

CREATE TABLE IF NOT EXISTS management_account_bindings (
    binding_ref TEXT PRIMARY KEY CHECK (binding_ref LIKE 'local:%'),
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'aws'),
    execution_profile TEXT NOT NULL DEFAULT 'aws'
      CHECK (execution_profile IN ('aws', 'localstack')),
    account_id TEXT NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    role_arn TEXT NOT NULL,
    region TEXT NOT NULL,
    network_binding_ref TEXT NOT NULL CHECK (network_binding_ref LIKE 'local:%'),
    state_binding_ref TEXT NOT NULL CHECK (state_binding_ref LIKE 'local:%'),
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^[a-f0-9]{64}$'),
    external_id_secret_ref TEXT NOT NULL CHECK (external_id_secret_ref LIKE 'local:%'),
    reconciler_spiffe_id TEXT NOT NULL CHECK (reconciler_spiffe_id LIKE 'spiffe://%'),
    receipt_public_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
      (execution_profile = 'aws' AND account_id <> '000000000000'
       AND role_arn ~ '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$')
      OR
      (execution_profile = 'localstack' AND account_id = '000000000000' AND role_arn = '')
    ),
    UNIQUE (tenant_id, deployment_id),
    UNIQUE (account_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS management_artifact_approvals (
    digest_ref TEXT PRIMARY KEY CHECK (digest_ref ~ '^approved:sha256:[a-f0-9]{64}$'),
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('application', 'harness', 'infrastructure', 'policy', 'dspy', 'compatibility')),
    status TEXT NOT NULL CHECK (status IN ('approved', 'revoked')),
    approved_by_issuer TEXT NOT NULL,
    approved_by_subject TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS management_deployments (
    deployment_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    binding_ref TEXT NOT NULL REFERENCES management_account_bindings(binding_ref),
    incarnation UUID NOT NULL,
    desired_generation BIGINT NOT NULL DEFAULT 0 CHECK (desired_generation >= 0),
    observed_generation BIGINT NOT NULL DEFAULT 0 CHECK (observed_generation >= 0),
    desired_manifest JSONB,
    desired_manifest_digest TEXT,
    observed_manifest_digest TEXT,
    state TEXT NOT NULL DEFAULT 'registered'
      CHECK (state IN ('registered', 'planning', 'awaiting_approval', 'provisioning', 'verifying', 'active', 'updating', 'rolling_back', 'recovery_required', 'suspended', 'offboarding', 'retention_pending', 'deleted')),
    next_fencing_token BIGINT NOT NULL DEFAULT 1 CHECK (next_fencing_token > 0),
    last_health_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, deployment_id),
    CHECK (observed_generation <= desired_generation)
);

CREATE TABLE IF NOT EXISTS management_operations (
    operation_id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES management_deployments(deployment_id),
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    idempotency_key TEXT NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('provision', 'configure', 'upgrade', 'rollback', 'suspend', 'resume', 'offboard', 'delete', 'backup', 'recover')),
    manifest_digest TEXT NOT NULL,
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^[a-f0-9]{64}$'),
    plan_hash TEXT,
    expected_generation BIGINT NOT NULL,
    target_generation BIGINT NOT NULL,
    fencing_token BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planning'
      CHECK (status IN ('planning', 'awaiting_approval', 'approved', 'claimed', 'applying', 'verifying', 'succeeded', 'failed', 'cancelled', 'recovery_required')),
    actor_issuer TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    approval_required BOOLEAN NOT NULL DEFAULT true,
    claimed_by TEXT,
    claimed_phase TEXT CHECK (claimed_phase IN ('plan', 'apply')),
    claim_command_id UUID,
    claimed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    last_error_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, idempotency_key),
    UNIQUE (deployment_id, fencing_token),
    CHECK (target_generation = expected_generation + 1)
);

CREATE TABLE IF NOT EXISTS management_operation_approvals (
    operation_id UUID PRIMARY KEY REFERENCES management_operations(operation_id),
    manifest_digest TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    approver_issuer TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_operation_events (
    event_id BIGSERIAL PRIMARY KEY,
    operation_id UUID NOT NULL REFERENCES management_operations(operation_id),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (operation_id, sequence)
);

CREATE TABLE IF NOT EXISTS management_operation_receipts (
    operation_id UUID PRIMARY KEY REFERENCES management_operations(operation_id),
    deployment_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL,
    command_id UUID NOT NULL,
    manifest_digest TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    observed_generation BIGINT NOT NULL,
    resource_inventory JSONB NOT NULL,
    verification_summary JSONB NOT NULL,
    provider_update_id TEXT,
    receipt_digest TEXT NOT NULL,
    receipt_signature TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_outbox (
    outbox_id BIGSERIAL PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_management_operations_ready
  ON management_operations (status, created_at)
  WHERE status IN ('approved', 'claimed', 'applying', 'verifying');
CREATE INDEX IF NOT EXISTS idx_management_outbox_pending
  ON management_outbox (outbox_id) WHERE published_at IS NULL;

COMMIT;
