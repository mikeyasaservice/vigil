from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException


@dataclass(frozen=True)
class CustomerIdentity:
    issuer: str
    subject_id: str
    token_id: str


def current_customer(authorization: str | None = Header(default=None)) -> CustomerIdentity:
    """Verify customer identity while ignoring all tenant and role claims.

    Tenant membership and roles are resolved from durable management state after
    signature, issuer, audience, lifetime and subject validation.
    """
    issuer = os.getenv("VIGIL_SAAS_AUTH_ISSUER", "")
    audience = os.getenv("VIGIL_SAAS_AUTH_AUDIENCE", "")
    public_key = os.getenv("VIGIL_SAAS_AUTH_PUBLIC_KEY", "")
    algorithm = os.getenv("VIGIL_SAAS_AUTH_ALGORITHM", "")
    if not issuer or not audience or not public_key or algorithm not in {"EdDSA", "RS256"}:
        raise HTTPException(status_code=503, detail="SaaS authentication trust is unavailable")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="SaaS bearer token required")
    try:
        payload = jwt.decode(
            authorization.removeprefix("Bearer ").strip(),
            public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={"require": ["sub", "iss", "aud", "exp", "iat", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="SaaS bearer token is invalid") from exc
    subject = str(payload.get("sub", ""))
    token_id = str(payload.get("jti", ""))
    if not subject or not token_id:
        raise HTTPException(status_code=401, detail="SaaS bearer token is incomplete")
    issued_at = datetime.fromtimestamp(int(payload["iat"]), timezone.utc)
    expires_at = datetime.fromtimestamp(int(payload["exp"]), timezone.utc)
    now = datetime.now(timezone.utc)
    if issued_at > now + timedelta(seconds=30) or expires_at - issued_at > timedelta(minutes=10):
        raise HTTPException(status_code=401, detail="SaaS bearer token lifetime is invalid")
    return CustomerIdentity(issuer=issuer, subject_id=subject, token_id=token_id)
