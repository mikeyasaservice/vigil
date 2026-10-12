BEGIN;

ALTER TABLE management_operator_scopes
  DROP CONSTRAINT IF EXISTS management_operator_scopes_role_check;
ALTER TABLE management_operator_scopes
  ADD CONSTRAINT management_operator_scopes_role_check
  CHECK (role IN (
    'platform_admin', 'deployment_operator', 'deployment_approver', 'auditor',
    'support_operator', 'support_approver', 'break_glass_approver'
  ));

CREATE TABLE IF NOT EXISTS management_identity_providers (
    provider_id TEXT PRIMARY KEY CHECK (provider_id ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
    protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    issuer TEXT NOT NULL UNIQUE,
    audience TEXT NOT NULL,
    oidc_jwks JSONB,
    oidc_algorithms TEXT[] NOT NULL DEFAULT ARRAY['RS256']::TEXT[],
    required_acr TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    required_amr TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    saml_sso_url TEXT,
    saml_entity_id TEXT,
    saml_acs_url TEXT,
    saml_signing_certificate TEXT,
    max_session_seconds INTEGER NOT NULL DEFAULT 600
      CHECK (max_session_seconds BETWEEN 60 AND 600),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
      (protocol = 'oidc' AND oidc_jwks IS NOT NULL
       AND saml_sso_url IS NULL AND saml_signing_certificate IS NULL)
      OR
      (protocol = 'saml' AND oidc_jwks IS NULL AND saml_sso_url IS NOT NULL
       AND saml_entity_id IS NOT NULL AND saml_acs_url IS NOT NULL
       AND saml_signing_certificate IS NOT NULL)
    ),
    CHECK (cardinality(required_acr) > 0 OR cardinality(required_amr) > 0)
);

ALTER TABLE management_identity_providers
  DROP CONSTRAINT IF EXISTS management_identity_providers_assurance_check;
UPDATE management_identity_providers
   SET required_amr = ARRAY['mfa']::TEXT[], updated_at = now()
 WHERE cardinality(required_acr) = 0 AND cardinality(required_amr) = 0;
ALTER TABLE management_identity_providers
  ADD CONSTRAINT management_identity_providers_assurance_check
  CHECK (cardinality(required_acr) > 0 OR cardinality(required_amr) > 0);

CREATE TABLE IF NOT EXISTS management_enterprise_users (
    provider_id TEXT NOT NULL REFERENCES management_identity_providers(provider_id),
    external_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    display_name TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    scim_version UUID NOT NULL DEFAULT gen_random_uuid(),
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, external_id),
    UNIQUE (provider_id, user_name)
);

CREATE TABLE IF NOT EXISTS management_enterprise_groups (
    provider_id TEXT NOT NULL REFERENCES management_identity_providers(provider_id),
    external_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    scim_version UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, external_id),
    UNIQUE (provider_id, display_name)
);

CREATE TABLE IF NOT EXISTS management_enterprise_group_members (
    provider_id TEXT NOT NULL,
    group_external_id TEXT NOT NULL,
    user_external_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, group_external_id, user_external_id),
    FOREIGN KEY (provider_id, group_external_id)
      REFERENCES management_enterprise_groups(provider_id, external_id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id, user_external_id)
      REFERENCES management_enterprise_users(provider_id, external_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS management_scim_tokens (
    token_id UUID PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES management_identity_providers(provider_id),
    token_digest TEXT NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by_issuer TEXT NOT NULL,
    created_by_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS management_saml_auth_requests (
    request_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES management_identity_providers(provider_id),
    relay_state_digest TEXT NOT NULL UNIQUE CHECK (relay_state_digest ~ '^[a-f0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS management_saml_assertion_replay (
    provider_id TEXT NOT NULL REFERENCES management_identity_providers(provider_id),
    assertion_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, assertion_id)
);

CREATE TABLE IF NOT EXISTS management_operator_access_requests (
    request_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL,
    access_kind TEXT NOT NULL CHECK (access_kind IN ('support', 'break_glass')),
    requested_actions TEXT[] NOT NULL CHECK (cardinality(requested_actions) BETWEEN 1 AND 16),
    requested_resources TEXT[] NOT NULL CHECK (cardinality(requested_resources) BETWEEN 1 AND 32),
    justification TEXT NOT NULL CHECK (length(justification) BETWEEN 10 AND 2000),
    ticket_ref TEXT NOT NULL CHECK (length(ticket_ref) BETWEEN 1 AND 200),
    incident_ref TEXT,
    requester_issuer TEXT NOT NULL,
    requester_subject TEXT NOT NULL,
    requester_token_id TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    requested_duration_seconds INTEGER NOT NULL CHECK (requested_duration_seconds BETWEEN 60 AND 900),
    status TEXT NOT NULL DEFAULT 'pending_customer'
      CHECK (status IN ('pending_customer', 'pending_provider', 'approved', 'active',
                        'denied', 'revoked', 'expired', 'completed')),
    customer_approved_at TIMESTAMPTZ,
    customer_approver_issuer TEXT,
    customer_approver_subject TEXT,
    revoked_at TIMESTAMPTZ,
    revoked_by_kind TEXT CHECK (revoked_by_kind IN ('customer', 'operator', 'scim', 'expiry', 'system')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, request_digest),
    UNIQUE (tenant_id, deployment_id, request_id),
    FOREIGN KEY (tenant_id, deployment_id)
      REFERENCES management_deployments(tenant_id, deployment_id),
    CHECK ((access_kind = 'support' AND incident_ref IS NULL)
        OR (access_kind = 'break_glass' AND incident_ref IS NOT NULL
            AND requested_duration_seconds <= 300))
);

ALTER TABLE management_operator_access_requests
  DROP CONSTRAINT IF EXISTS management_operator_access_requests_revoked_by_kind_check;
ALTER TABLE management_operator_access_requests
  ADD CONSTRAINT management_operator_access_requests_revoked_by_kind_check
  CHECK (revoked_by_kind IN ('customer', 'operator', 'scim', 'expiry', 'system'));

CREATE TABLE IF NOT EXISTS management_operator_access_approvals (
    request_id UUID NOT NULL REFERENCES management_operator_access_requests(request_id) ON DELETE CASCADE,
    approval_kind TEXT NOT NULL CHECK (approval_kind IN ('provider', 'break_glass_corroborator')),
    approver_issuer TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver_issuer, approver_subject),
    UNIQUE (request_id, approval_kind)
);

CREATE TABLE IF NOT EXISTS management_operator_access_sessions (
    session_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE REFERENCES management_operator_access_requests(request_id),
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    operator_issuer TEXT NOT NULL,
    operator_subject TEXT NOT NULL,
    token_digest TEXT NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[a-f0-9]{64}$'),
    revocation_epoch BIGINT NOT NULL DEFAULT 1 CHECK (revocation_epoch > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'completed')),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, deployment_id, request_id)
      REFERENCES management_operator_access_requests(tenant_id, deployment_id, request_id)
);

CREATE TABLE IF NOT EXISTS management_support_gateway_bindings (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    gateway_spiffe_id TEXT NOT NULL UNIQUE CHECK (gateway_spiffe_id LIKE 'spiffe://%'),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, deployment_id),
    FOREIGN KEY (tenant_id, deployment_id)
      REFERENCES management_deployments(tenant_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS management_operator_access_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES management_tenants(tenant_id),
    deployment_id TEXT NOT NULL,
    request_id UUID,
    session_id UUID,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('operator', 'customer', 'scim', 'system')),
    actor_issuer TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    reason_code TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR previous_event_hash ~ '^[a-f0-9]{64}$'),
    event_hash TEXT NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_management_enterprise_users_active
  ON management_enterprise_users (provider_id, external_id) WHERE active;
CREATE INDEX IF NOT EXISTS idx_management_operator_access_active
  ON management_operator_access_sessions (tenant_id, deployment_id, expires_at)
  WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_management_operator_access_audit_tenant
  ON management_operator_access_audit (tenant_id, occurred_at DESC, audit_id DESC);

CREATE OR REPLACE FUNCTION management_operator_audit_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'operator access audit records are immutable';
END;
$$;

DROP TRIGGER IF EXISTS management_operator_access_audit_no_update
  ON management_operator_access_audit;
CREATE TRIGGER management_operator_access_audit_no_update
  BEFORE UPDATE OR DELETE ON management_operator_access_audit
  FOR EACH ROW EXECUTE FUNCTION management_operator_audit_immutable();

COMMIT;
