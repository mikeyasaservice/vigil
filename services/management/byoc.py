from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID
from services.management.auth import OperatorIdentity
from services.management.contracts import BYOCEnrollmentRequest

_ENROLLMENT_NAMESPACE = uuid.UUID("9c62025e-d484-4f67-b892-22101971dd85")


def _secret() -> bytes:
    encoded = os.getenv("VIGIL_BYOC_ENROLLMENT_SECRET", "")
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
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


def issue_connector_certificate(
    csr_pem: str, expected_spiffe_id: str
) -> dict[str, str]:
    """Issue a short-lived client certificate for an already authenticated binding."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = [
            str(value)
            for value in sans.get_values_for_type(x509.UniformResourceIdentifier)
        ]
        if uris != [expected_spiffe_id]:
            raise ValueError("CSR identity does not match the authenticated connector")
        if (
            sans.get_values_for_type(x509.DNSName)
            or sans.get_values_for_type(x509.IPAddress)
            or sans.get_values_for_type(x509.RFC822Name)
        ):
            raise ValueError("CSR contains an unauthorized alternate identity")
        public_key = csr.public_key()
        if not isinstance(
            public_key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)
        ):
            raise ValueError("CSR key algorithm is not approved")
        if isinstance(public_key, ec.EllipticCurvePublicKey) and not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError("CSR elliptic curve is not approved")

        ca_cert_path = Path(os.environ["VIGIL_BYOC_CA_CERT_PATH"])
        ca_key_path = Path(os.environ["VIGIL_BYOC_CA_KEY_PATH"])
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(
            ca_key_path.read_bytes(), password=None
        )
        if ca_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != ca_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            raise ValueError(
                "BYOC certificate authority key does not match its certificate"
            )
        constraints = ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not constraints.ca:
            raise ValueError("BYOC certificate authority certificate is not a CA")
    except (KeyError, OSError, ValueError, TypeError, x509.ExtensionNotFound) as exc:
        raise RuntimeError(
            "BYOC certificate authority is unavailable or CSR is invalid"
        ) from exc

    now = datetime.now(timezone.utc)
    expires = min(now + timedelta(hours=24), ca_cert.not_valid_after_utc)
    if expires <= now + timedelta(minutes=5):
        raise RuntimeError("BYOC certificate authority expires too soon")
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(expected_spiffe_id)]
            ),
            critical=False,
        )
    )
    algorithm = (
        None if isinstance(ca_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    )
    certificate = builder.sign(ca_key, algorithm)
    return {
        "client_certificate": certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "certificate_expires_at": expires.isoformat().replace("+00:00", "Z"),
        "certificate_serial": format(certificate.serial_number, "x"),
    }
