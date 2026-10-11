from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from services.management.auth import current_operator


ISSUER = "https://identity.example"
AUDIENCE = "vigil-management"


@pytest.fixture()
def signing_key(monkeypatch: pytest.MonkeyPatch) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    monkeypatch.setenv("VIGIL_MANAGEMENT_AUTH_ISSUER", ISSUER)
    monkeypatch.setenv("VIGIL_MANAGEMENT_AUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("VIGIL_MANAGEMENT_AUTH_PUBLIC_KEY", public_key)
    monkeypatch.setenv("VIGIL_MANAGEMENT_AUTH_ALGORITHM", "EdDSA")
    return key


def token(key: Ed25519PrivateKey, *, audience: str = AUDIENCE, lifetime: timedelta = timedelta(minutes=5)) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": audience,
            "sub": "operator-a",
            "jti": "token-a",
            "iat": now,
            "exp": now + lifetime,
            "roles": ["platform_admin"],
            "tenant_id": "caller-controlled-tenant",
        },
        key,
        algorithm="EdDSA",
    )


def test_operator_identity_uses_verified_issuer_subject_and_ignores_authority_claims(signing_key: Ed25519PrivateKey) -> None:
    identity = current_operator("Bearer " + token(signing_key))
    assert identity.issuer == ISSUER
    assert identity.subject_id == "operator-a"
    assert identity.token_id == "token-a"
    assert not hasattr(identity, "roles")


@pytest.mark.parametrize(
    "encoded",
    [
        lambda key: token(key, audience="foreign-audience"),
        lambda key: token(key, lifetime=timedelta(minutes=11)),
    ],
)
def test_operator_rejects_wrong_audience_and_overlong_tokens(signing_key: Ed25519PrivateKey, encoded) -> None:
    with pytest.raises(HTTPException) as raised:
        current_operator("Bearer " + encoded(signing_key))
    assert raised.value.status_code == 401
