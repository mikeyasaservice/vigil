from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from starlette.requests import Request

from services.management.app import _reconciler_identity


def certificate(spiffe_id: str) -> str:
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    held = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "phase3-reconciler")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "phase3-test-ca")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=False)
        .sign(key, algorithm=None)
    )
    return held.public_bytes(serialization.Encoding.PEM).decode()


def request_with_scope(scope: dict) -> Request:
    return Request({"type": "http", "method": "POST", "path": "/internal", "headers": [], **scope})


def test_reconciler_identity_comes_from_tls_client_certificate() -> None:
    identity = "spiffe://vigil.io/management/reconciler-a"
    request = request_with_scope({"extensions": {"tls": {"client_cert_chain": [certificate(identity)]}}})
    assert _reconciler_identity(request) == identity


def test_reconciler_identity_comes_from_server_owned_connection_state() -> None:
    identity = "spiffe://vigil.io/management/reconciler-a"
    request = request_with_scope({"state": {"vigil.verified_spiffe_id": identity}})
    assert _reconciler_identity(request) == identity


def test_headers_without_tls_certificate_cannot_authenticate_reconciler() -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/internal",
            "headers": [(b"x-vigil-verified-spiffe-id", b"spiffe://vigil.io/management/reconciler-a")],
        }
    )
    with pytest.raises(HTTPException) as raised:
        _reconciler_identity(request)
    assert raised.value.status_code == 401
