import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.agents.managed_execution import Ed25519Signer
from core.agents.managed_store import program_registry_payload, verify_program_registry_record


def record():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    row = {
        "tenant_id": "tenant-a",
        "program_id": "triage-dspy-v1",
        "program_digest": "sha256:program",
        "model_config_digest": "sha256:model",
        "dependency_digest": "sha256:deps",
        "status": "active",
        "authority_public_key": base64.urlsafe_b64encode(public).decode().rstrip("="),
    }
    row["artifact_signature"] = Ed25519Signer(private).sign(program_registry_payload(row))
    return row


def test_active_registry_record_requires_a_valid_tenant_signature():
    row = record()
    assert verify_program_registry_record(row)

    row["program_digest"] = "sha256:altered"
    assert not verify_program_registry_record(row)


def test_registry_signature_cannot_move_between_tenants():
    row = record()
    row["tenant_id"] = "tenant-b"
    assert not verify_program_registry_record(row)
