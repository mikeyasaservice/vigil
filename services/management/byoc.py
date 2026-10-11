from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import uuid
from datetime import timezone
from typing import Any

from services.management.auth import OperatorIdentity
from services.management.contracts import BYOCEnrollmentRequest

_ENROLLMENT_NAMESPACE = uuid.UUID("9c62025e-d484-4f67-b892-22101971dd85")


def _secret() -> bytes:
    encoded = os.getenv("VIGIL_BYOC_ENROLLMENT_SECRET", "")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise RuntimeError("BYOC enrollment authority is unavailable") from exc
    if len(raw) < 32:
        raise RuntimeError("BYOC enrollment authority is unavailable")
    return raw


def enrollment_material(
    request: BYOCEnrollmentRequest, actor: OperatorIdentity
) -> tuple[str, str, str]:
    """Derive retry-stable one-use material without storing the bearer secret."""
    identity = "\x1f".join(
        (
            actor.issuer,
            actor.subject_id,
            request.tenant_id,
            request.deployment_id,
            request.idempotency_key,
        )
    )
    enrollment_id = str(uuid.uuid5(_ENROLLMENT_NAMESPACE, identity))
    message = "\x1f".join(
        (
            enrollment_id,
            request.tenant_id,
            request.deployment_id,
            request.account_id,
            request.connector_spiffe_id,
            request.local_policy_digest,
            request.expires_at.astimezone(timezone.utc).isoformat(),
        )
    ).encode()
    token = (
        base64.urlsafe_b64encode(hmac.new(_secret(), message, hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return enrollment_id, token, hashlib.sha256(token.encode()).hexdigest()


def enrollment_proof(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "enrollment_id": str(row["enrollment_id"]),
        "tenant_id": str(row["tenant_id"]),
        "deployment_id": str(row["deployment_id"]),
        "account_id": str(row["account_id"]),
        "connector_spiffe_id": str(row["connector_spiffe_id"]),
        "local_policy_digest": str(row["local_policy_digest"]),
    }
