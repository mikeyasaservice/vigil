BEGIN;

ALTER TABLE management_account_bindings
  DROP CONSTRAINT IF EXISTS management_account_bindings_execution_profile_check;

ALTER TABLE management_account_bindings
  DROP CONSTRAINT IF EXISTS management_account_bindings_check;

ALTER TABLE management_account_bindings
  ADD CONSTRAINT management_account_bindings_execution_profile_check
  CHECK (
    (execution_profile = 'aws' AND account_id <> '000000000000'
     AND role_arn ~ '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$')
    OR
    (execution_profile = 'localstack' AND account_id = '000000000000' AND role_arn = '')
    OR
    (execution_profile = 'byoc' AND account_id <> '000000000000' AND role_arn = '')
    OR
    (execution_profile = 'byoc-localstack' AND account_id ~ '^[0-9]{12}$' AND role_arn = '')
  );

CREATE TABLE IF NOT EXISTS management_byoc_enrollments (
    enrollment_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL REFERENCES management_deployments(deployment_id),
    account_id TEXT NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    connector_spiffe_id TEXT NOT NULL CHECK (connector_spiffe_id LIKE 'spiffe://%'),
    local_policy_digest TEXT NOT NULL CHECK (local_policy_digest ~ '^[a-f0-9]{64}$'),
    token_digest TEXT NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    idempotency_key TEXT NOT NULL,
    requested_by_issuer TEXT NOT NULL,
    requested_by_subject TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'consumed', 'revoked', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS management_byoc_connectors (
    deployment_id TEXT PRIMARY KEY REFERENCES management_deployments(deployment_id),
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    enrollment_id UUID NOT NULL UNIQUE REFERENCES management_byoc_enrollments(enrollment_id),
    account_id TEXT NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    connector_spiffe_id TEXT NOT NULL UNIQUE CHECK (connector_spiffe_id LIKE 'spiffe://%'),
    connector_public_key TEXT NOT NULL,
    local_policy_digest TEXT NOT NULL CHECK (local_policy_digest ~ '^[a-f0-9]{64}$'),
    trust_version BIGINT NOT NULL DEFAULT 1 CHECK (trust_version > 0),
    revocation_epoch BIGINT NOT NULL DEFAULT 1 CHECK (revocation_epoch > 0),
    management_enabled BOOLEAN NOT NULL DEFAULT true,
    last_health_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_health_sequence >= 0),
    last_health_at TIMESTAMPTZ,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (tenant_id, deployment_id),
    UNIQUE (account_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS management_byoc_health_events (
    event_id BIGSERIAL PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES management_byoc_connectors(deployment_id),
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    incarnation UUID NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_kind TEXT NOT NULL
      CHECK (event_kind IN ('heartbeat', 'release', 'capacity', 'gap', 'revocation')),
    event_digest TEXT NOT NULL CHECK (event_digest ~ '^[a-f0-9]{64}$'),
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, incarnation, sequence)
);

CREATE TABLE IF NOT EXISTS management_byoc_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL REFERENCES management_deployments(deployment_id),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('operator', 'connector')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    reason_code TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_management_byoc_enrollment_pending
  ON management_byoc_enrollments (deployment_id, expires_at)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_management_byoc_health_recent
  ON management_byoc_health_events (deployment_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_management_byoc_audit_tenant
  ON management_byoc_audit (tenant_id, created_at DESC);

COMMIT;
