from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from services.management.byoc import issue_connector_certificate


@pytest.fixture()
def certificate_authority(monkeypatch, tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autobot BYOC test CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, None)
    )
    cert_path = tmp_path / "ca.crt"
    key_path = tmp_path / "ca.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("VIGIL_BYOC_CA_CERT_PATH", str(cert_path))
    monkeypatch.setenv("VIGIL_BYOC_CA_KEY_PATH", str(key_path))
    return certificate


def csr(spiffe_id: str, extra_dns: bool = False) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.UniformResourceIdentifier(spiffe_id)]
    if extra_dns:
        names.append(x509.DNSName("unauthorized.example"))
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(serialization.Encoding.PEM).decode()


def test_issued_certificate_is_short_lived_client_only_and_spiffe_bound(
    certificate_authority,
) -> None:
    identity = "spiffe://customer.example/autobot/connector-a"
    result = issue_connector_certificate(csr(identity), identity)
    leaf = x509.load_pem_x509_certificate(result["client_certificate"].encode())
    assert leaf.issuer == certificate_authority.subject
    assert leaf.not_valid_after_utc <= datetime.now(timezone.utc) + timedelta(
        hours=24, minutes=1
    )
    assert leaf.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.UniformResourceIdentifier) == [identity]


@pytest.mark.parametrize(
    ("requested", "expected", "extra_dns"),
    [
        (
            "spiffe://customer.example/autobot/connector-b",
            "spiffe://customer.example/autobot/connector-a",
            False,
        ),
        (
            "spiffe://customer.example/autobot/connector-a",
            "spiffe://customer.example/autobot/connector-a",
            True,
        ),
    ],
)
def test_certificate_issuance_rejects_identity_substitution(
    certificate_authority, requested: str, expected: str, extra_dns: bool
) -> None:
    with pytest.raises(RuntimeError, match="CSR is invalid"):
        issue_connector_certificate(csr(requested, extra_dns), expected)
