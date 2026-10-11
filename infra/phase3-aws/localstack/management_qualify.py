#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import psycopg2
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID


DATABASE_URL = "postgresql://postgres:phase3-local-only@127.0.0.1:55439/vigil_management"
ISSUER = "https://issuer.vigil.local"
AUDIENCE = "vigil-management"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def write(path: Path, value: bytes | str, mode: int = 0o600) -> None:
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(mode)


def issue_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    *,
    server: bool = False,
    spiffe_id: str | None = None,
) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names: list[x509.GeneralName] = []
    if server:
        names.extend([x509.DNSName("management.vigil.local"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    if spiffe_id:
        names.append(x509.UniformResourceIdentifier(spiffe_id))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def create_trust(trust: Path) -> dict[str, object]:
    trust.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vigil Phase 3 Local CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write(trust / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    server_cert, server_key = issue_certificate(ca_key, ca_cert, "management.vigil.local", server=True)
    write(trust / "server.crt", server_cert, 0o644)
    write(trust / "server.key", server_key)
    operator_cert, operator_key = issue_certificate(ca_key, ca_cert, "qualification-operator")
    write(trust / "operator.crt", operator_cert, 0o644)
    write(trust / "operator.key", operator_key)

    receipt_public: dict[str, str] = {}
    for tenant in ("a", "b"):
        spiffe_id = f"spiffe://vigil.local/reconciler/tenant-{tenant}"
        cert, key = issue_certificate(ca_key, ca_cert, f"reconciler-{tenant}", spiffe_id=spiffe_id)
        write(trust / f"reconciler-{tenant}.crt", cert, 0o644)
        write(trust / f"reconciler-{tenant}.key", key)
        receipt_key = ed25519.Ed25519PrivateKey.generate()
        receipt_seed = receipt_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        write(trust / f"receipt-{tenant}.key", b64(receipt_seed))
        receipt_public[tenant] = b64(
            receipt_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    command_key = ed25519.Ed25519PrivateKey.generate()
    command_seed = command_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    command_public = b64(command_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    write(trust / "command-public.key", command_public)
    auth_key = ed25519.Ed25519PrivateKey.generate()
    auth_public_pem = auth_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {
        "command_private": b64(command_seed),
        "receipt_public": receipt_public,
        "auth_key": auth_key,
        "auth_public_pem": auth_public_pem,
    }


def canonical_digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def seed(repo: Path, work: Path, trust_material: dict[str, object]) -> None:
    with psycopg2.connect(DATABASE_URL) as connection, connection.cursor() as cursor:
        cursor.execute((repo / "infra/management/database/001_management_plane.sql").read_text())
        cursor.execute((repo / "infra/management/database/002_binding_execution_profile.sql").read_text())
        cursor.execute(
            "TRUNCATE management_outbox, management_operation_receipts, management_operation_events, "
            "management_operation_approvals, management_operations, management_deployments, "
            "management_artifact_approvals, management_account_bindings, management_operator_scopes, "
            "management_tenants RESTART IDENTITY CASCADE"
        )
        for tenant in ("a", "b"):
            tenant_id = f"tenant-{tenant}"
            deployment_id = f"deployment-local-{tenant}"
            manifest = json.loads((work / tenant / "manifest.json").read_text())
            binding = json.loads((work / tenant / "binding.json").read_text())
            cursor.execute(
                "INSERT INTO management_tenants (tenant_id, display_name) VALUES (%s, %s)",
                (tenant_id, f"Local tenant {tenant.upper()}"),
            )
            cursor.execute(
                """INSERT INTO management_operator_scopes
                   (issuer, subject_id, tenant_id, role, membership_version)
                   VALUES (%s, %s, %s, 'deployment_operator', 1),
                          (%s, %s, %s, 'deployment_approver', 1)""",
                (ISSUER, f"requester-{tenant}", tenant_id, ISSUER, f"approver-{tenant}", tenant_id),
            )
            cursor.execute(
                """INSERT INTO management_account_bindings
                   (binding_ref, tenant_id, deployment_id, provider, execution_profile, account_id,
                    role_arn, region, network_binding_ref, state_binding_ref, external_id_secret_ref,
                    binding_digest, reconciler_spiffe_id, receipt_public_key)
                   VALUES (%s, %s, %s, 'aws', 'localstack', '000000000000', '', 'us-east-1',
                           %s, %s, 'local:synthetic-no-external-id', %s, %s, %s)""",
                (
                    binding["binding_ref"], tenant_id, deployment_id, binding["network_binding_ref"],
                    binding["state_binding_ref"], canonical_digest(binding), binding["reconciler_spiffe_id"],
                    trust_material["receipt_public"][tenant],
                ),
            )
            kinds = {
                manifest["releases"]["application"]["digest_ref"]: "application",
                manifest["releases"]["harness"]["digest_ref"]: "harness",
                manifest["releases"]["infrastructure"]["digest_ref"]: "infrastructure",
                manifest["releases"]["policy"]["digest_ref"]: "policy",
                manifest["releases"]["dspy"]["digest_ref"]: "dspy",
                manifest["operations"]["rollback_compatibility_ref"]: "compatibility",
            }
            for digest, kind in kinds.items():
                cursor.execute(
                    """INSERT INTO management_artifact_approvals
                       (digest_ref, artifact_kind, status, approved_by_issuer, approved_by_subject)
                       VALUES (%s, %s, 'approved', %s, 'local-release-approver')
                       ON CONFLICT (digest_ref) DO UPDATE SET artifact_kind=EXCLUDED.artifact_kind, status='approved'""",
                    (digest, kind, ISSUER),
                )


def token(key: ed25519.Ed25519PrivateKey, subject: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": subject, "jti": f"qualification-{subject}", "iat": now, "exp": now + timedelta(minutes=9)},
        key,
        algorithm="EdDSA",
    )


class API:
    def __init__(self, trust: Path):
        self.context = ssl.create_default_context(cafile=str(trust / "ca.pem"))
        self.context.load_cert_chain(str(trust / "operator.crt"), str(trust / "operator.key"))

    def call(self, method: str, path: str, body: object | None = None, bearer: str | None = None, expected: int = 200) -> dict:
        connection = http.client.HTTPSConnection("127.0.0.1", 8444, context=self.context, timeout=60)
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if method == "POST" and path.endswith("/operations"):
            headers["Idempotency-Key"] = f"qualification-{path.split('/')[3]}"
        connection.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        if response.status != expected:
            raise RuntimeError(f"{method} {path} returned {response.status}: {raw.decode(errors='replace')}")
        return json.loads(raw) if raw else {}


def run_reconciler(repo: Path, work: Path, tenant: str, operation_id: str, phase: str) -> None:
    subprocess.run(
        [
            "go", "run", "./cmd/reconciler", "-operation", operation_id, "-phase", phase,
            "-binding", str(work / tenant / "binding.json"), "-command-public-key", str(work / "trust/command-public.key"),
            "-runner-id", f"qualification-{tenant}-{phase}",
        ],
        cwd=repo / "infra/phase3-aws",
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": "vigil-localstack-development-only", "GOCACHE": "/tmp/vigil-phase3-go-cache"},
        check=True,
    )


def write_stack_outputs(work: Path, tenant: str, operation_id: str) -> None:
    environment = {
        **os.environ,
        "PULUMI_CONFIG_PASSPHRASE": "vigil-localstack-development-only",
        "PULUMI_HOME": str(work / tenant / "pulumi-home"),
        "PULUMI_BACKEND_URL": f"file://{work / tenant / 'state'}",
    }
    result = subprocess.run(
        ["pulumi", "--cwd", str(work / tenant / "workspace" / f"deployment-local-{tenant}" / operation_id / "source"),
         "stack", "output", "--stack", f"deployment-local-{tenant}", "--json"],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    (work / tenant / "outputs.json").write_text(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    repo, work = args.repo.resolve(), args.work_root.resolve()
    trust = work / "trust"
    material = create_trust(trust)
    seed(repo, work, material)
    env = {
        **os.environ,
        "PYTHONPATH": str(repo),
        "MANAGEMENT_DATABASE_URL": DATABASE_URL,
        "VIGIL_MANAGEMENT_AUTH_ISSUER": ISSUER,
        "VIGIL_MANAGEMENT_AUTH_AUDIENCE": AUDIENCE,
        "VIGIL_MANAGEMENT_AUTH_PUBLIC_KEY": str(material["auth_public_pem"]),
        "VIGIL_MANAGEMENT_AUTH_ALGORITHM": "EdDSA",
        "VIGIL_MANAGEMENT_COMMAND_PRIVATE_KEY": str(material["command_private"]),
        "VIGIL_MANAGEMENT_BIND": "127.0.0.1:8444",
        "VIGIL_MANAGEMENT_TLS_CERT": str(trust / "server.crt"),
        "VIGIL_MANAGEMENT_TLS_KEY": str(trust / "server.key"),
        "VIGIL_MANAGEMENT_CLIENT_CA": str(trust / "ca.pem"),
    }
    log = (work / "management.log").open("wb")
    server = subprocess.Popen([sys.executable, "-m", "services.management.serve"], cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
    api = API(trust)
    try:
        for _ in range(60):
            try:
                api.call("GET", "/readyz")
                break
            except Exception:
                if server.poll() is not None:
                    raise RuntimeError(f"management service exited; see {work / 'management.log'}")
                time.sleep(0.5)
        else:
            raise RuntimeError("management service did not become ready")

        operations: dict[str, str] = {}
        for tenant in ("a", "b"):
            manifest = json.loads((work / tenant / "manifest.json").read_text())
            requester = token(material["auth_key"], f"requester-{tenant}")
            result = api.call(
                "POST", f"/v1/deployments/deployment-local-{tenant}/operations",
                {"operation_kind": "provision", "manifest": manifest}, requester, 202,
            )
            operations[tenant] = result["operation_id"]

        wrong_context = ssl.create_default_context(cafile=str(trust / "ca.pem"))
        wrong_context.load_cert_chain(str(trust / "reconciler-a.crt"), str(trust / "reconciler-a.key"))
        connection = http.client.HTTPSConnection("127.0.0.1", 8444, context=wrong_context, timeout=30)
        connection.request(
            "POST", f"/internal/v1/operations/{operations['b']}/claim",
            body=json.dumps({"phase": "plan", "runner_id": "wrong-tenant-runner"}),
            headers={"Content-Type": "application/json", "X-Vigil-Runner-Id": "wrong-tenant-runner"},
        )
        wrong = connection.getresponse(); wrong.read(); connection.close()
        if wrong.status != 403:
            raise RuntimeError(f"tenant A reconciler certificate received {wrong.status} for tenant B claim")

        for tenant in ("a", "b"):
            operation_id = operations[tenant]
            requester = token(material["auth_key"], f"requester-{tenant}")
            approver = token(material["auth_key"], f"approver-{tenant}")
            run_reconciler(repo, work, tenant, operation_id, "plan")
            planned = api.call("GET", f"/v1/operations/{operation_id}", bearer=requester)
            approval = {
                "manifest_digest": planned["manifest_digest"], "plan_hash": planned["plan_hash"],
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
            }
            api.call("POST", f"/v1/operations/{operation_id}/approve", approval, approver)
            run_reconciler(repo, work, tenant, operation_id, "apply")
            complete = api.call("GET", f"/v1/operations/{operation_id}", bearer=requester)
            if complete["status"] != "succeeded":
                raise RuntimeError(f"tenant {tenant} operation ended in {complete['status']}")
            write_stack_outputs(work, tenant, operation_id)
        print("PASS: management API, PostgreSQL, real mTLS workload identity, two-person approval, saved Pulumi plans, LocalStack apply, and signed receipts completed for tenants A and B")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill(); server.wait(timeout=5)
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
