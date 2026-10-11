from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from services.management.saas_auth import CustomerIdentity, current_customer
from services.management.saas_tickets import issue_route_ticket

ISSUER = "https://customers.example"
AUDIENCE = "vigil-saas"


@pytest.fixture()
def signing_key(monkeypatch: pytest.MonkeyPatch) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    monkeypatch.setenv("VIGIL_SAAS_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("VIGIL_SAAS_AUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("VIGIL_SAAS_AUTH_PUBLIC_KEY", public_key)
    monkeypatch.setenv("VIGIL_SAAS_AUTH_ALGORITHM", "EdDSA")
    monkeypatch.setenv("VIGIL_ROUTE_TICKET_PRIVATE_KEY", private_key)
    monkeypatch.setenv("VIGIL_ROUTE_TICKET_ISSUER", "https://routing.example")
    monkeypatch.setenv("VIGIL_ROUTE_TICKET_AUDIENCE", "vigil-data-plane")
    return key


def customer_token(key: Ed25519PrivateKey, **claims) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-a",
        "jti": "session-a",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "tenant_id": "tenant-forged",
        "roles": ["platform_admin"],
    }
    payload.update(claims)
    return jwt.encode(payload, key, algorithm="EdDSA")


def test_customer_identity_ignores_tenant_and_role_claims(signing_key: Ed25519PrivateKey) -> None:
    identity = current_customer("Bearer " + customer_token(signing_key))
    assert identity == CustomerIdentity(ISSUER, "user-a", "session-a")
    assert not hasattr(identity, "tenant_id")
    assert not hasattr(identity, "roles")


def test_customer_identity_rejects_foreign_audience(signing_key: Ed25519PrivateKey) -> None:
    with pytest.raises(HTTPException) as raised:
        current_customer("Bearer " + customer_token(signing_key, aud="foreign"))
    assert raised.value.status_code == 401


def test_route_ticket_binds_server_resolved_route(signing_key: Ed25519PrivateKey) -> None:
    route = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "incarnation": "d8fae038-dd3b-48b6-ab1b-60aab34d88a1",
        "cell_id": "cell-us-east-1",
        "route_ref": "local:cell-us-east-1-router",
        "route_epoch": 4,
        "membership_version": 7,
    }
    encoded, ticket_id, expires_at = issue_route_ticket(
        route, CustomerIdentity(ISSUER, "user-a", "session-a")
    )
    public_key = (
        signing_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    claims = jwt.decode(
        encoded,
        public_key,
        algorithms=["EdDSA"],
        issuer="https://routing.example",
        audience="vigil-data-plane",
    )
    assert claims["jti"] == ticket_id
    assert claims["tenant_id"] == "tenant-a"
    assert claims["deployment_id"] == "deployment-a"
    assert claims["route_epoch"] == 4
    assert claims["membership_version"] == 7
    assert datetime.fromtimestamp(claims["exp"], timezone.utc) <= datetime.now(
        timezone.utc
    ) + timedelta(seconds=61)
    assert expires_at > datetime.now(timezone.utc)
