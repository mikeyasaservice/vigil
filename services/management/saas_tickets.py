from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from services.management.saas_auth import CustomerIdentity
from services.management.store import ManagementUnavailable


def issue_route_ticket(route: dict[str, Any], actor: CustomerIdentity) -> tuple[str, str, datetime]:
    private_key = os.getenv("VIGIL_ROUTE_TICKET_PRIVATE_KEY", "")
    issuer = os.getenv("VIGIL_ROUTE_TICKET_ISSUER", "")
    audience = os.getenv("VIGIL_ROUTE_TICKET_AUDIENCE", "")
    if not private_key or not issuer or not audience:
        raise ManagementUnavailable("route ticket signing trust is unavailable")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=60)
    ticket_id = str(uuid.uuid4())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": actor.subject_id,
        "jti": ticket_id,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "tenant_id": route["tenant_id"],
        "deployment_id": route["deployment_id"],
        "deployment_incarnation": str(route["incarnation"]),
        "cell_id": route["cell_id"],
        "route_ref": route["route_ref"],
        "route_epoch": int(route["route_epoch"]),
        "membership_version": int(route["membership_version"]),
    }
    try:
        encoded = jwt.encode(claims, private_key, algorithm="EdDSA")
    except (ValueError, jwt.PyJWTError) as exc:
        raise ManagementUnavailable("route ticket signer is invalid") from exc
    return encoded, ticket_id, expires_at
