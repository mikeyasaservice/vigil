from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from core.agents.managed_execution import Ed25519Signer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _signer(encoded: str) -> Ed25519Signer:
    padded = encoded + "=" * (-len(encoded) % 4)
    return Ed25519Signer(Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded)))


def issue_reconcile_command(operation: dict[str, Any], manifest: dict[str, Any], phase: str) -> dict[str, Any]:
    private_key = os.getenv("VIGIL_MANAGEMENT_COMMAND_PRIVATE_KEY", "")
    if not private_key:
        raise RuntimeError("management command signing authority is unavailable")
    now = datetime.now(timezone.utc)
    command = {
        "schema_version": 1,
        "command_id": str(operation["claim_command_id"]),
        "operation_id": str(operation["operation_id"]),
        "phase": phase,
        "tenant_id": str(operation["tenant_id"]),
        "deployment_id": str(operation["deployment_id"]),
        "manifest_digest": str(operation["manifest_digest"]),
        "binding_digest": str(operation["binding_digest"]),
        "plan_hash": str(operation["plan_hash"]) if operation.get("plan_hash") else None,
        "fencing_token": int(operation["fencing_token"]),
        "target_generation": int(operation["target_generation"]),
        "placement": manifest["placement"],
        "releases": manifest["releases"],
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    }
    signer = _signer(private_key)
    return {"command": command, "signature": signer.sign(command)}


def public_key_from_private(private_key: str) -> str:
    return _signer(private_key).public_key_b64
