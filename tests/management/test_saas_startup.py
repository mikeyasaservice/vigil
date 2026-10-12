from __future__ import annotations

import base64
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from services.management.serve import configuration


def configure_base(monkeypatch: pytest.MonkeyPatch) -> Ed25519PrivateKey:
    command_key = Ed25519PrivateKey.generate().private_bytes_raw()
    values = {
        "MANAGEMENT_DATABASE_URL": "postgresql://unused",
        "VIGIL_MANAGEMENT_AUTH_ISSUER": "https://operators.example",
        "VIGIL_MANAGEMENT_AUTH_AUDIENCE": "vigil-management",
        "VIGIL_MANAGEMENT_AUTH_PUBLIC_KEY": "mounted-operator-public-key",
        "VIGIL_MANAGEMENT_AUTH_ALGORITHM": "EdDSA",
        "VIGIL_MANAGEMENT_COMMAND_PRIVATE_KEY": base64.urlsafe_b64encode(command_key)
        .decode()
        .rstrip("="),
        "VIGIL_MANAGEMENT_TLS_CERT": "/mounted/server.crt",
        "VIGIL_MANAGEMENT_TLS_KEY": "/mounted/server.key",
        "VIGIL_MANAGEMENT_CLIENT_CA": "/mounted/client-ca.crt",
        "VIGIL_MANAGEMENT_PROFILE": "shared-saas",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    for name in (
        "VIGIL_SAAS_AUTH_ISSUER",
        "VIGIL_SAAS_AUTH_AUDIENCE",
        "VIGIL_SAAS_AUTH_PUBLIC_KEY",
        "VIGIL_SAAS_AUTH_ALGORITHM",
        "VIGIL_ROUTE_TICKET_ISSUER",
        "VIGIL_ROUTE_TICKET_AUDIENCE",
        "VIGIL_ROUTE_TICKET_PRIVATE_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    return Ed25519PrivateKey.generate()


def configure_saas(
    monkeypatch: pytest.MonkeyPatch, route_key: Ed25519PrivateKey
) -> None:
    values = {
        "VIGIL_SAAS_AUTH_ISSUER": "https://customers.example",
        "VIGIL_SAAS_AUTH_AUDIENCE": "vigil-saas",
        "VIGIL_SAAS_AUTH_PUBLIC_KEY": "mounted-customer-public-key",
        "VIGIL_SAAS_AUTH_ALGORITHM": "EdDSA",
        "VIGIL_ROUTE_TICKET_ISSUER": "https://routing.example",
        "VIGIL_ROUTE_TICKET_AUDIENCE": "vigil-data-plane",
        "VIGIL_ROUTE_TICKET_PRIVATE_KEY": route_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_shared_saas_startup_requires_customer_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_base(monkeypatch)
    with pytest.raises(RuntimeError, match="VIGIL_SAAS_AUTH_ISSUER"):
        configuration()


def test_shared_saas_startup_rejects_invalid_route_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_key = configure_base(monkeypatch)
    configure_saas(monkeypatch, route_key)
    monkeypatch.setenv("VIGIL_ROUTE_TICKET_PRIVATE_KEY", "invalid")
    with pytest.raises(RuntimeError, match="ROUTE_TICKET.*invalid"):
        configuration()


def test_shared_saas_startup_enforces_mutual_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_key = configure_base(monkeypatch)
    configure_saas(monkeypatch, route_key)
    held = configuration()
    assert held.verify_mode == ssl.CERT_REQUIRED


def test_byoc_startup_requires_strong_enrollment_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    configure_base(monkeypatch)
    monkeypatch.setenv("VIGIL_MANAGEMENT_PROFILE", "byoc-control")
    monkeypatch.setenv(
        "VIGIL_BYOC_ENROLLMENT_SECRET",
        base64.urlsafe_b64encode(b"short").decode().rstrip("="),
    )
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        configuration()
    monkeypatch.setenv(
        "VIGIL_BYOC_ENROLLMENT_SECRET",
        base64.urlsafe_b64encode(b"phase5-enrollment-authority-secret")
        .decode()
        .rstrip("="),
    )
    with pytest.raises(RuntimeError, match="VIGIL_BYOC_CA_CERT_PATH"):
        configuration()
    ca_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autobot BYOC test CA")])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, None)
    )
    ca_cert_path = tmp_path / "ca.crt"
    ca_key_path = tmp_path / "ca.key"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("VIGIL_BYOC_CA_CERT_PATH", str(ca_cert_path))
    monkeypatch.setenv("VIGIL_BYOC_CA_KEY_PATH", str(ca_key_path))
    held = configuration()
    assert held.verify_mode == ssl.CERT_REQUIRED
