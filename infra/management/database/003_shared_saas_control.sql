BEGIN;

CREATE TABLE IF NOT EXISTS management_organizations (
    organization_id TEXT PRIMARY KEY CHECK (organization_id ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
      CHECK (status IN ('active', 'suspended', 'offboarding', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_organization_tenants (
    organization_id TEXT NOT NULL REFERENCES management_organizations(organization_id),
    tenant_id TEXT PRIMARY KEY REFERENCES management_tenants(tenant_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_tenant_memberships (
    membership_id BIGSERIAL PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    role TEXT NOT NULL CHECK (role IN ('tenant_admin', 'analyst', 'approver', 'viewer')),
    membership_version BIGINT NOT NULL CHECK (membership_version > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject_id, tenant_id, role)
);

CREATE TABLE IF NOT EXISTS management_saas_cells (
    cell_id TEXT PRIMARY KEY CHECK (cell_id ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
    region TEXT NOT NULL,
    route_ref TEXT NOT NULL UNIQUE CHECK (route_ref LIKE 'local:%'),
    isolation_profile TEXT NOT NULL DEFAULT 'dedicated-data-plane'
      CHECK (isolation_profile = 'dedicated-data-plane'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'draining', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_saas_tenant_bindings (
    tenant_id TEXT PRIMARY KEY REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL,
    cell_id TEXT NOT NULL REFERENCES management_saas_cells(cell_id),
    route_epoch BIGINT NOT NULL DEFAULT 1 CHECK (route_epoch > 0),
    data_plane_spiffe_id TEXT NOT NULL UNIQUE CHECK (data_plane_spiffe_id LIKE 'spiffe://%'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'moving', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, deployment_id),
    FOREIGN KEY (tenant_id, deployment_id)
      REFERENCES management_deployments(tenant_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS management_route_ticket_audit (
    ticket_id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL,
    cell_id TEXT NOT NULL REFERENCES management_saas_cells(cell_id),
    membership_version BIGINT NOT NULL,
    route_epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_quota_policies (
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    dimension TEXT NOT NULL CHECK (dimension IN ('api_requests', 'agent_runs', 'model_tokens', 'tool_calls', 'ingest_bytes', 'stored_bytes')),
    hard_limit BIGINT NOT NULL CHECK (hard_limit > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds BETWEEN 60 AND 2678400),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dimension)
);

CREATE TABLE IF NOT EXISTS management_usage_windows (
    tenant_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),
    committed_amount BIGINT NOT NULL DEFAULT 0 CHECK (committed_amount >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dimension, window_started_at),
    FOREIGN KEY (tenant_id, dimension)
      REFERENCES management_quota_policies(tenant_id, dimension)
);

CREATE TABLE IF NOT EXISTS management_usage_reservations (
    reservation_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    reserved_amount BIGINT NOT NULL CHECK (reserved_amount > 0),
    committed_amount BIGINT CHECK (committed_amount >= 0),
    policy_version BIGINT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'committed', 'released')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, invocation_id),
    FOREIGN KEY (tenant_id, deployment_id)
      REFERENCES management_saas_tenant_bindings(tenant_id, deployment_id),
    FOREIGN KEY (tenant_id, dimension, window_started_at)
      REFERENCES management_usage_windows(tenant_id, dimension, window_started_at)
);

CREATE TABLE IF NOT EXISTS management_saas_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'workload')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    reason_code TEXT NOT NULL,
    resource_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_management_memberships_subject
  ON management_tenant_memberships (issuer, subject_id, tenant_id)
  WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_management_usage_reservations_active
  ON management_usage_reservations (tenant_id, dimension, expires_at)
  WHERE status = 'reserved';
CREATE INDEX IF NOT EXISTS idx_management_saas_audit_tenant
  ON management_saas_audit (tenant_id, created_at DESC);

COMMIT;
