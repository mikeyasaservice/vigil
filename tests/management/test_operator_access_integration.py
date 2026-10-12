from __future__ import annotations

import base64
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import psycopg2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from lxml import etree
from services.management.auth import OperatorIdentity
from services.management.contracts import OperatorAccessRequest
from services.management.enterprise_identity import EnterpriseIdentityStore
from services.management.operator_access import OperatorAccessStore
from services.management.saas_auth import CustomerIdentity
from services.management.store import ManagementConflict, ManagementDenied
from signxml import XMLSigner, methods

ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = os.getenv("PHASE3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="PHASE3_TEST_DATABASE_URL is not configured"
)

ISSUER = "https://workforce.autobot.example"


@pytest.fixture()
def access_state():
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        connection.autocommit = True
        with connection.cursor() as cursor:
            for migration in (
                "001_management_plane.sql",
                "002_binding_execution_profile.sql",
                "003_shared_saas_control.sql",
                "005_enterprise_identity_operator_access.sql",
            ):
                cursor.execute((ROOT / "infra/management/database" / migration).read_text())
            cursor.execute(
                """
                TRUNCATE management_operator_access_audit,
                  management_operator_access_sessions, management_operator_access_approvals,
                  management_operator_access_requests, management_saml_assertion_replay,
                  management_saml_auth_requests, management_scim_tokens,
                  management_enterprise_group_members, management_enterprise_groups,
                  management_enterprise_users, management_identity_providers,
                  management_tenant_memberships, management_deployments,
                  management_account_bindings, management_operator_scopes,
                  management_tenants RESTART IDENTITY CASCADE;

                INSERT INTO management_tenants (tenant_id, display_name)
                VALUES ('tenant-a', 'Tenant A'), ('tenant-b', 'Tenant B');
                INSERT INTO management_account_bindings
                  (binding_ref, tenant_id, deployment_id, provider, execution_profile,
                   account_id, role_arn, region, network_binding_ref, state_binding_ref,
                   binding_digest, external_id_secret_ref, reconciler_spiffe_id, receipt_public_key)
                VALUES
                  ('local:binding-a', 'tenant-a', 'deployment-a', 'aws', 'localstack',
                   '000000000000', '', 'us-east-1', 'local:network-a', 'local:state-a',
                   repeat('a', 64), 'local:external-a', 'spiffe://autobot.example/reconciler/a', 'key-a'),
                  ('local:binding-b', 'tenant-b', 'deployment-b', 'aws', 'localstack',
                   '000000000000', '', 'us-east-1', 'local:network-b', 'local:state-b',
                   repeat('b', 64), 'local:external-b', 'spiffe://autobot.example/reconciler/b', 'key-b');
                INSERT INTO management_deployments
                  (deployment_id, tenant_id, binding_ref, incarnation,
                   desired_generation, observed_generation, state)
                VALUES
                  ('deployment-a', 'tenant-a', 'local:binding-a',
                   '11111111-1111-4111-8111-111111111111', 1, 1, 'active'),
                  ('deployment-b', 'tenant-b', 'local:binding-b',
                   '22222222-2222-4222-8222-222222222222', 1, 1, 'active');
                INSERT INTO management_identity_providers
                  (provider_id, protocol, issuer, audience, oidc_jwks, oidc_algorithms, required_amr)
                VALUES
                  ('workforce-primary', 'oidc', 'https://workforce.autobot.example',
                   'autobot-management', '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"primary","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}',
                   ARRAY['EdDSA'], ARRAY['mfa']);
                INSERT INTO management_enterprise_users
                  (provider_id, external_id, user_name, display_name)
                VALUES
                  ('workforce-primary', 'requester', 'requester@example.com', 'Requester'),
                  ('workforce-primary', 'approver-one', 'approver-one@example.com', 'Approver One'),
                  ('workforce-primary', 'approver-two', 'approver-two@example.com', 'Approver Two');
                INSERT INTO management_operator_scopes
                  (issuer, subject_id, tenant_id, role, membership_version)
                VALUES
                  ('https://workforce.autobot.example', 'requester', 'tenant-a', 'support_operator', 1),
                  ('https://workforce.autobot.example', 'approver-one', 'tenant-a', 'support_approver', 1),
                  ('https://workforce.autobot.example', 'approver-one', 'tenant-a', 'break_glass_approver', 1),
                  ('https://workforce.autobot.example', 'approver-two', 'tenant-a', 'break_glass_approver', 1);
                INSERT INTO management_tenant_memberships
                  (issuer, subject_id, tenant_id, role, membership_version)
                VALUES ('https://customers.autobot.example', 'customer-approver', 'tenant-a', 'approver', 1);
                INSERT INTO management_support_gateway_bindings
                  (tenant_id, deployment_id, gateway_spiffe_id)
                VALUES
                  ('tenant-a', 'deployment-a', 'spiffe://autobot.example/support-gateway/a'),
                  ('tenant-b', 'deployment-b', 'spiffe://autobot.example/support-gateway/b');
                """
            )
    requester = OperatorIdentity(
        ISSUER, "requester", "requester-token", "workforce-primary", "requester-session", ("mfa",)
    )
    approver_one = OperatorIdentity(
        ISSUER,
        "approver-one",
        "approver-one-token",
        "workforce-primary",
        "approver-one-session",
        ("mfa",),
    )
    approver_two = OperatorIdentity(
        ISSUER,
        "approver-two",
        "approver-two-token",
        "workforce-primary",
        "approver-two-session",
        ("mfa",),
    )
    customer = CustomerIdentity(
        "https://customers.autobot.example", "customer-approver", "customer-session"
    )
    return (
        OperatorAccessStore(DATABASE_URL),
        EnterpriseIdentityStore(DATABASE_URL),
        requester,
        approver_one,
        approver_two,
        customer,
    )


def support_request(**overrides) -> OperatorAccessRequest:
    values = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "access_kind": "support",
        "actions": ["deployment.health.read"],
        "resources": ["deployment-a/health"],
        "justification": "Investigate customer-approved health incident",
        "ticket_ref": "SUP-1001",
        "duration_seconds": 300,
    }
    values.update(overrides)
    return OperatorAccessRequest.model_validate(values)


def approve_and_activate(store, requester, approver, customer):
    request = store.create_request(support_request(), requester)
    request_id = str(request["request_id"])
    digest = request["request_digest"]
    store.customer_approve(request_id, digest, customer)
    with pytest.raises(ManagementDenied):
        store.provider_approve(request_id, digest, requester)
    store.provider_approve(request_id, digest, approver)
    session, token = store.activate(request_id, requester)
    return request, session, token


def test_t07_requires_customer_approved_exact_scope_and_enforces_revocation(access_state) -> None:
    store, _, requester, approver, _, customer = access_state
    request, session, token = approve_and_activate(store, requester, approver, customer)
    session_id = str(session["session_id"])

    allowed = store.authorize(
        session_id,
        token,
        "deployment.health.read",
        "deployment-a/health",
        requester,
        "spiffe://autobot.example/support-gateway/a",
    )
    assert allowed["allowed"] is True
    wrong_gateway = store.authorize(
        session_id,
        token,
        "deployment.health.read",
        "deployment-a/health",
        requester,
        "spiffe://autobot.example/support-gateway/b",
    )
    assert wrong_gateway["allowed"] is False
    assert wrong_gateway["reason_code"] == "support_gateway_mismatch"

    for action, resource in (
        ("tenant.data.read", "deployment-a/findings"),
        ("tool.invoke", "deployment-a/integrations/edr"),
        ("backup.download", "deployment-a/backups/latest"),
        ("pod.exec", "deployment-a/pods/api"),
        ("workload.role.change", "deployment-a/roles/worker"),
        ("deployment.health.read", "deployment-b/health"),
    ):
        denied = store.authorize(
            session_id,
            token,
            action,
            resource,
            requester,
            "spiffe://autobot.example/support-gateway/a",
        )
        assert denied["allowed"] is False
        assert denied["reason_code"] == "outside_approved_scope"

    store.revoke_by_customer(str(request["request_id"]), "tenant-a", customer)
    revoked = store.authorize(
        session_id,
        token,
        "deployment.health.read",
        "deployment-a/health",
        requester,
        "spiffe://autobot.example/support-gateway/a",
    )
    assert revoked["allowed"] is False
    assert revoked["reason_code"] == "session_revoked"

    audit = store.list_customer_audit("tenant-a", customer)
    assert any(
        event["action"] == "deployment.health.read" and event["outcome"] == "allowed"
        for event in audit
    )
    assert sum(event["outcome"] == "denied" for event in audit) >= 6
    assert audit[0]["event_hash"]


def test_t07_scim_deprovisioning_revokes_active_session(access_state) -> None:
    store, identity, requester, approver, _, customer = access_state
    _, session, token = approve_and_activate(store, requester, approver, customer)
    identity.deactivate_scim_user("workforce-primary", "requester")
    decision = store.authorize(
        str(session["session_id"]),
        token,
        "deployment.health.read",
        "deployment-a/health",
        requester,
        "spiffe://autobot.example/support-gateway/a",
    )
    assert decision["allowed"] is False
    assert decision["reason_code"] == "session_revoked"


def test_t07_break_glass_requires_customer_and_two_distinct_provider_approvers(
    access_state,
) -> None:
    store, _, requester, approver_one, approver_two, customer = access_state
    request = store.create_request(
        support_request(
            access_kind="break_glass",
            actions=["pod.exec"],
            resources=["deployment-a/pods/api"],
            incident_ref="INC-9001",
            duration_seconds=180,
            ticket_ref="SUP-9001",
        ),
        requester,
    )
    request_id, digest = str(request["request_id"]), request["request_digest"]
    store.customer_approve(request_id, digest, customer)
    first = store.provider_approve(request_id, digest, approver_one)
    assert first["status"] == "pending_provider"
    with pytest.raises(ManagementConflict):
        store.activate(request_id, requester)
    second = store.provider_approve(request_id, digest, approver_two)
    assert second["status"] == "approved"
    session, token = store.activate(request_id, requester)
    decision = store.authorize(
        str(session["session_id"]),
        token,
        "pod.exec",
        "deployment-a/pods/api",
        requester,
        "spiffe://autobot.example/support-gateway/a",
    )
    assert decision["allowed"] is True


def test_t07_expired_session_denies_even_with_unexpired_secret(access_state) -> None:
    store, _, requester, approver, _, customer = access_state
    _, session, token = approve_and_activate(store, requester, approver, customer)
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE management_operator_access_sessions SET expires_at = %s WHERE session_id = %s",
                (datetime.now(UTC) - timedelta(seconds=1), str(session["session_id"])),
            )
    decision = store.authorize(
        str(session["session_id"]),
        token,
        "deployment.health.read",
        "deployment-a/health",
        requester,
        "spiffe://autobot.example/support-gateway/a",
    )
    assert decision["allowed"] is False
    assert decision["reason_code"] == "session_expired"


def test_oidc_federation_uses_pinned_jwks_assurance_and_scim_state(access_state) -> None:
    _, identity, _, _, _, _ = access_state
    key = Ed25519PrivateKey.generate()
    public = base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).decode().rstrip("=")
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE management_identity_providers
                   SET oidc_jwks = %s::jsonb, required_acr = ARRAY['urn:autobot:assurance:phishing-resistant'],
                       required_amr = ARRAY['mfa']
                 WHERE provider_id = 'workforce-primary'
                """,
                ('{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"primary","x":"' + public + '"}]}',),
            )
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "autobot-management",
            "sub": "requester",
            "jti": str(uuid.uuid4()),
            "sid": str(uuid.uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "acr": "urn:autobot:assurance:phishing-resistant",
            "amr": ["mfa", "hwk"],
            "role": "platform_admin",
            "tenant_id": "tenant-b",
        },
        key,
        algorithm="EdDSA",
        headers={"kid": "primary"},
    )
    principal = identity.authenticate(token)
    assert principal.provider_id == "workforce-primary"
    assert principal.subject_id == "requester"
    assert "mfa" in principal.assurance

    weak = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "autobot-management",
            "sub": "requester",
            "jti": str(uuid.uuid4()),
            "sid": str(uuid.uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "acr": "password-only",
            "amr": ["pwd"],
        },
        key,
        algorithm="EdDSA",
        headers={"kid": "primary"},
    )
    with pytest.raises(ManagementDenied):
        identity.authenticate(weak)


def test_saml_federation_is_signed_target_bound_and_replay_protected(
    access_state, monkeypatch
) -> None:
    _, identity, _, _, _, _ = access_state
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autobot test SAML IdP")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(signing_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO management_identity_providers
                  (provider_id, protocol, issuer, audience, oidc_jwks,
                   required_acr, saml_sso_url, saml_entity_id, saml_acs_url, saml_signing_certificate)
                VALUES ('saml-workforce', 'saml', 'https://saml.autobot.example/idp',
                        'autobot-management', NULL, ARRAY['urn:autobot:assurance:phishing-resistant'],
                        'https://saml.autobot.example/sso',
                        'https://saml.autobot.example/idp',
                        'https://management.autobot.example/v1/sso/saml/saml-workforce/acs', %s);
                INSERT INTO management_enterprise_users
                  (provider_id, external_id, user_name, display_name)
                VALUES ('saml-workforce', 'saml-operator', 'saml-operator@example.com', 'SAML Operator');
                """,
                (certificate_pem,),
            )
    login = identity.begin_saml_login("saml-workforce")
    response = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        },
        ID="_response-1",
        Version="2.0",
        IssueInstant=now.isoformat().replace("+00:00", "Z"),
        Destination="https://management.autobot.example/v1/sso/saml/saml-workforce/acs",
        InResponseTo=login["request_id"],
    )
    assertion = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
        ID="_assertion-1",
        Version="2.0",
        IssueInstant=now.isoformat().replace("+00:00", "Z"),
    )
    etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
    ).text = "https://saml.autobot.example/idp"
    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    etree.SubElement(
        subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
    ).text = "saml-operator"
    confirmation = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    etree.SubElement(
        confirmation,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
        InResponseTo=login["request_id"],
        Recipient="https://management.autobot.example/v1/sso/saml/saml-workforce/acs",
        NotOnOrAfter=(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    )
    conditions = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
        NotBefore=(now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        NotOnOrAfter=(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    )
    restriction = etree.SubElement(
        conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
    )
    etree.SubElement(
        restriction, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    ).text = "autobot-management"
    authn_statement = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
        AuthnInstant=now.isoformat().replace("+00:00", "Z"),
        SessionIndex="saml-session-1",
    )
    authn_context = etree.SubElement(
        authn_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
    )
    etree.SubElement(
        authn_context, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
    ).text = "urn:autobot:assurance:phishing-resistant"
    response.append(assertion)
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    ).sign(assertion, key=private_pem, cert=certificate_pem, reference_uri="#_assertion-1")
    response.replace(assertion, signed)
    encoded = base64.b64encode(etree.tostring(response)).decode()

    session_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("AUTOBOT_FEDERATED_SESSION_ISSUER", "https://sessions.autobot.example")
    monkeypatch.setenv("AUTOBOT_FEDERATED_SESSION_AUDIENCE", "autobot-management")
    monkeypatch.setenv(
        "AUTOBOT_FEDERATED_SESSION_PRIVATE_KEY",
        session_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    monkeypatch.setenv(
        "AUTOBOT_FEDERATED_SESSION_PUBLIC_KEY",
        session_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode(),
    )
    token, _ = identity.consume_saml_assertion("saml-workforce", encoded, login["relay_state"])
    principal = identity.authenticate(token)
    assert principal.subject_id == "saml-operator"
    assert principal.provider_id == "saml-workforce"
    with pytest.raises(ManagementDenied):
        identity.consume_saml_assertion("saml-workforce", encoded, login["relay_state"])
