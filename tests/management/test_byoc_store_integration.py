from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import pytest
from core.agents.managed_execution import Ed25519Signer, Ed25519Verifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError
from services.management.auth import OperatorIdentity
from services.management.byoc import enrollment_material, enrollment_proof
from services.management.contracts import BYOCEnrollmentRequest, BYOCHealthEvent
from services.management.store import ManagementConflict, ManagementDenied, ManagementStore

ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = os.getenv("PHASE3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="PHASE3_TEST_DATABASE_URL is not configured"
)


def test_go_and_python_share_byoc_canonical_signatures() -> None:
    fixture = json.loads((ROOT / "contracts/fixtures/byoc-connector-v1.json").read_text())
    public_key = base64.urlsafe_b64decode(
        fixture["public_key"] + "=" * (-len(fixture["public_key"]) % 4)
    )
    verifier = Ed25519Verifier(Ed25519PublicKey.from_public_bytes(public_key), "phase5-fixture")
    verifier.verify(fixture["proof"], fixture["proof_signature"])
    verifier.verify(fixture["health"], fixture["health_signature"])


@pytest.fixture()
def byoc_state(monkeypatch) -> tuple[ManagementStore, OperatorIdentity, BYOCEnrollmentRequest]:
    assert DATABASE_URL is not None
    monkeypatch.setenv(
        "VIGIL_BYOC_ENROLLMENT_SECRET",
        base64.urlsafe_b64encode(b"phase5-test-enrollment-secret-32-bytes").decode().rstrip("="),
    )
    connection = psycopg2.connect(DATABASE_URL)
    connection.autocommit = True
    with connection.cursor() as cursor:
        for migration in (
            "001_management_plane.sql",
            "002_binding_execution_profile.sql",
            "003_shared_saas_control.sql",
            "004_byoc_control.sql",
        ):
            cursor.execute((ROOT / "infra/management/database" / migration).read_text())
        cursor.execute(
            """
            TRUNCATE management_byoc_audit, management_byoc_health_events,
              management_byoc_connectors, management_byoc_enrollments,
              management_saas_audit, management_usage_reservations,
              management_usage_windows, management_quota_policies,
              management_route_ticket_audit, management_tenant_memberships,
              management_saas_tenant_bindings, management_saas_cells,
              management_organization_tenants, management_organizations,
              management_outbox, management_operation_receipts, management_operation_events,
              management_operation_approvals, management_operations, management_deployments,
              management_artifact_approvals, management_account_bindings,
              management_operator_scopes, management_tenants
            RESTART IDENTITY CASCADE
            """
        )
        cursor.execute(
            """
            INSERT INTO management_tenants (tenant_id, display_name)
            VALUES ('tenant-a', 'Tenant A'), ('tenant-b', 'Tenant B');
            INSERT INTO management_operator_scopes
              (issuer, subject_id, tenant_id, role, membership_version)
            VALUES ('https://issuer.example', 'operator-a', 'tenant-a', 'deployment_operator', 1);
            INSERT INTO management_account_bindings
              (binding_ref, tenant_id, deployment_id, provider, execution_profile,
               account_id, role_arn, region, network_binding_ref, state_binding_ref,
               binding_digest, external_id_secret_ref, reconciler_spiffe_id, receipt_public_key)
            VALUES
              ('local:byoc-a', 'tenant-a', 'deployment-a', 'aws', 'byoc-localstack',
               '111111111111', '', 'us-east-1', 'local:network-a', 'local:state-a',
               repeat('a', 64), 'local:no-central-secret',
               'spiffe://customer.example/vigil/connector-a', 'unused-enrollment-key'),
              ('local:byoc-b', 'tenant-b', 'deployment-b', 'aws', 'byoc-localstack',
               '222222222222', '', 'us-east-1', 'local:network-b', 'local:state-b',
               repeat('b', 64), 'local:no-central-secret',
               'spiffe://customer.example/vigil/connector-b', 'unused-enrollment-key');
            INSERT INTO management_deployments
              (deployment_id, tenant_id, binding_ref, incarnation,
               desired_generation, observed_generation, state)
            VALUES
              ('deployment-a', 'tenant-a', 'local:byoc-a',
               'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 1, 1, 'active'),
              ('deployment-b', 'tenant-b', 'local:byoc-b',
               'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 1, 1, 'active');
            """
        )
    connection.close()
    actor = OperatorIdentity("https://issuer.example", "operator-a", "operator-session")
    request = BYOCEnrollmentRequest(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        account_id="111111111111",
        connector_spiffe_id="spiffe://customer.example/vigil/connector-a",
        local_policy_digest="c" * 64,
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        idempotency_key="enroll-a-1",
    )
    return ManagementStore(DATABASE_URL), actor, request


def enroll(
    store: ManagementStore, actor: OperatorIdentity, request: BYOCEnrollmentRequest
) -> tuple[Ed25519Signer, dict]:
    enrollment_id, token, token_digest = enrollment_material(request, actor)
    row = store.create_byoc_enrollment(request, actor, enrollment_id, token_digest)
    signer = Ed25519Signer(Ed25519PrivateKey.generate())
    connector = store.enroll_byoc_connector(
        enrollment_id,
        token,
        request.account_id,
        request.local_policy_digest,
        signer.public_key_b64,
        signer.sign(enrollment_proof(row)),
        request.connector_spiffe_id,
    )
    return signer, connector


def health_event(
    signer: Ed25519Signer, sequence: int = 1, status: str = "healthy"
) -> BYOCHealthEvent:
    value = {
        "incarnation": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "sequence": sequence,
        "event_kind": "heartbeat",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "revocation_epoch": 1,
        "payload": {
            "status": status,
            "observed_generation": 1,
            "release_digest": "d" * 64,
            "backlog_count": 0,
            "dropped_count": 0,
            "storage_watermark_percent": 20,
        },
        "signature": "x" * 40,
    }
    normalized = BYOCHealthEvent.model_validate(value)
    unsigned = normalized.model_dump(mode="json", exclude={"signature"})
    return normalized.model_copy(update={"signature": signer.sign(unsigned)})


def test_enrollment_requires_target_key_and_mtls_identity(byoc_state) -> None:
    store, actor, request = byoc_state
    enrollment_id, token, token_digest = enrollment_material(request, actor)
    row = store.create_byoc_enrollment(request, actor, enrollment_id, token_digest)
    replay = store.create_byoc_enrollment(request, actor, enrollment_id, token_digest)
    assert replay["enrollment_id"] == row["enrollment_id"]
    signer = Ed25519Signer(Ed25519PrivateKey.generate())
    signature = signer.sign(enrollment_proof(row))
    with pytest.raises(ManagementDenied):
        store.enroll_byoc_connector(
            enrollment_id,
            token,
            request.account_id,
            request.local_policy_digest,
            signer.public_key_b64,
            signature,
            "spiffe://customer.example/vigil/connector-b",
        )
    connector = store.enroll_byoc_connector(
        enrollment_id,
        token,
        request.account_id,
        request.local_policy_digest,
        signer.public_key_b64,
        signature,
        request.connector_spiffe_id,
    )
    assert connector["tenant_id"] == "tenant-a"
    with pytest.raises(ManagementConflict):
        store.create_byoc_enrollment(request, actor, enrollment_id, token_digest)
    with pytest.raises(ManagementDenied):
        store.enroll_byoc_connector(
            enrollment_id,
            token,
            request.account_id,
            request.local_policy_digest,
            signer.public_key_b64,
            signature,
            request.connector_spiffe_id,
        )


def test_signed_health_is_contiguous_idempotent_and_allowlisted(byoc_state) -> None:
    store, actor, request = byoc_state
    signer, _ = enroll(store, actor, request)
    event = health_event(signer)
    first = store.record_byoc_health("deployment-a", request.connector_spiffe_id, event)
    assert first["duplicate"] is False
    replay = ManagementStore(DATABASE_URL).record_byoc_health(
        "deployment-a", request.connector_spiffe_id, event
    )
    assert replay["duplicate"] is True
    altered = health_event(signer, status="degraded")
    with pytest.raises(ManagementConflict):
        store.record_byoc_health("deployment-a", request.connector_spiffe_id, altered)
    with pytest.raises(ManagementDenied):
        store.record_byoc_health(
            "deployment-b", request.connector_spiffe_id, health_event(signer, sequence=2)
        )
    with pytest.raises(ValidationError):
        BYOCHealthEvent.model_validate(
            {
                **event.model_dump(mode="json"),
                "payload": {
                    **event.payload.model_dump(mode="json"),
                    "raw_finding": "secret-canary",
                },
            }
        )


def test_revocation_is_durable_and_blocks_new_health(byoc_state) -> None:
    store, actor, request = byoc_state
    signer, _ = enroll(store, actor, request)
    revoked = store.revoke_byoc_management("tenant-a", "deployment-a", actor)
    assert revoked["management_enabled"] is False
    assert revoked["revocation_epoch"] == 2
    with pytest.raises(ManagementDenied):
        ManagementStore(DATABASE_URL).record_byoc_health(
            "deployment-a", request.connector_spiffe_id, health_event(signer)
        )
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT action FROM management_byoc_audit WHERE tenant_id = 'tenant-a' ORDER BY audit_id"
            )
            assert [row[0] for row in cursor.fetchall()] == [
                "enrollment.issue",
                "connector.enroll",
                "management.revoke",
            ]
