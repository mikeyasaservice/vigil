from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Header, HTTPException


@dataclass(frozen=True)
class OperatorIdentity:
    issuer: str
    subject_id: str
    token_id: str
    provider_id: str | None = None
    session_id: str | None = None
    assurance: tuple[str, ...] = ()


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="management bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="management bearer token required")
    return token


def current_operator(authorization: str | None = Header(default=None)) -> OperatorIdentity:
    """Verify an issuer-qualified operator token without accepting role claims.

    The public key is mounted as management-plane trust material. Tenant scope and
    roles are resolved from durable management state for every operation.
    """
    token = _bearer(authorization)
    mode = os.getenv("AUTOBOT_ENTERPRISE_IDENTITY_MODE", "legacy")
    if mode == "database":
        # Imported lazily to preserve the explicit legacy adapter without creating
        # an auth -> store -> auth import cycle.
        from services.management.enterprise_identity import EnterpriseIdentityStore
        from services.management.store import ManagementDenied, ManagementUnavailable

        try:
            principal = EnterpriseIdentityStore().authenticate(token)
        except ManagementDenied as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except ManagementUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return OperatorIdentity(
            issuer=principal.issuer,
            subject_id=principal.subject_id,
            token_id=principal.token_id,
            provider_id=principal.provider_id,
            session_id=principal.session_id,
            assurance=principal.assurance,
        )
    if mode != "legacy":
        raise HTTPException(status_code=503, detail="enterprise identity mode is invalid")

    issuer = os.getenv("VIGIL_MANAGEMENT_AUTH_ISSUER", "")
    audience = os.getenv("VIGIL_MANAGEMENT_AUTH_AUDIENCE", "")
    public_key = os.getenv("VIGIL_MANAGEMENT_AUTH_PUBLIC_KEY", "")
    algorithm = os.getenv("VIGIL_MANAGEMENT_AUTH_ALGORITHM", "")
    if not issuer or not audience or not public_key or algorithm not in {"EdDSA", "RS256"}:
        raise HTTPException(
            status_code=503, detail="management authentication trust is unavailable"
        )
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={"require": ["sub", "iss", "aud", "exp", "iat", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="management bearer token is invalid") from exc
    subject = str(payload.get("sub", ""))
    token_id = str(payload.get("jti", ""))
    if not subject or not token_id:
        raise HTTPException(status_code=401, detail="management bearer token is incomplete")
    issued_at = datetime.fromtimestamp(int(payload["iat"]), UTC)
    expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
    now = datetime.now(UTC)
    if issued_at > now + timedelta(seconds=30) or expires_at - issued_at > timedelta(minutes=10):
        raise HTTPException(status_code=401, detail="management bearer token lifetime is invalid")
    return OperatorIdentity(issuer=issuer, subject_id=subject, token_id=token_id)
