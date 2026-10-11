from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.agents.managed_execution import Ed25519Signer
from services.management.auth import OperatorIdentity
from services.management.contracts import DeploymentManifest
from services.management.store import ManagementConflict, ManagementDenied, ManagementStore, manifest_digest


ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = os.getenv("PHASE3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="PHASE3_TEST_DATABASE_URL is not configured")


def key_material() -> tuple[Ed25519Signer, str]:
    private = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return signer, base64.urlsafe_b64encode(public).decode().rstrip("=")


@pytest.fixture()
def management_state() -> tuple[ManagementStore, DeploymentManifest, OperatorIdentity, OperatorIdentity, Ed25519Signer]:
    assert DATABASE_URL is not None
    connection = psycopg2.connect(DATABASE_URL)
    connection.autocommit = True
    with connection.cursor() as cursor:
        cursor.execute((ROOT / "infra/management/database/001_management_plane.sql").read_text())
        cursor.execute(
            "TRUNCATE management_outbox, management_operation_receipts, management_operation_events, "
            "management_operation_approvals, management_operations, management_deployments, "
            "management_artifact_approvals, management_account_bindings, management_operator_scopes, "
            "management_tenants RESTART IDENTITY CASCADE"
        )
        signer, public_key = key_material()
        cursor.execute("INSERT INTO management_tenants (tenant_id, display_name) VALUES ('tenant-example-a', 'Tenant A')")
        cursor.execute(
            """
            INSERT INTO management_operator_scopes (issuer, subject_id, tenant_id, role, membership_version)
            VALUES ('https://issuer.example', 'requester', 'tenant-example-a', 'deployment_operator', 1),
                   ('https://issuer.example', 'approver', 'tenant-example-a', 'deployment_approver', 1)
            """
        )
        cursor.execute(
            """
            INSERT INTO management_account_bindings
              (binding_ref, tenant_id, deployment_id, provider, account_id, role_arn, region,
               network_binding_ref, state_binding_ref, external_id_secret_ref,
               binding_digest, reconciler_spiffe_id, receipt_public_key)
            VALUES
              ('local:approved-account-binding', 'tenant-example-a', 'deployment-example-a', 'aws',
               '111111111111', 'arn:aws:iam::111111111111:role/VigilProvisioner', 'us-east-1',
               'local:approved-network', 'local:approved-state', 'local:external-id',
               %s, 'spiffe://vigil.io/management/reconciler-a', %s)
            """,
            ("a" * 64, public_key),
        )
        manifest_value = json.loads((ROOT / "docs/architecture/contracts/deployment-manifest.example.json").read_text())
        artifact_kinds = {
            manifest_value["releases"]["application"]["digest_ref"]: "application",
            manifest_value["releases"]["harness"]["digest_ref"]: "harness",
            manifest_value["releases"]["infrastructure"]["digest_ref"]: "infrastructure",
            manifest_value["releases"]["policy"]["digest_ref"]: "policy",
            manifest_value["releases"]["dspy"]["digest_ref"]: "dspy",
            manifest_value["operations"]["rollback_compatibility_ref"]: "compatibility",
        }
        for digest_ref, kind in artifact_kinds.items():
            cursor.execute(
                """
                INSERT INTO management_artifact_approvals
                  (digest_ref, artifact_kind, status, approved_by_issuer, approved_by_subject)
                VALUES (%s, %s, 'approved', 'https://issuer.example', 'release-approver')
                """,
                (digest_ref, kind),
            )
    connection.close()
    return (
        ManagementStore(DATABASE_URL),
        DeploymentManifest.model_validate(manifest_value),
        OperatorIdentity("https://issuer.example", "requester", "requester-token"),
        OperatorIdentity("https://issuer.example", "approver", "approver-token"),
        signer,
    )


def test_durable_plan_approval_apply_receipt_and_cancellation_fence(management_state) -> None:
    store, manifest, requester, approver, receipt_signer = management_state
    spiffe_id = "spiffe://vigil.io/management/reconciler-a"
    operation = store.submit_operation(manifest, "provision", "provision-1", requester)

    claimed_plan, held_manifest = store.claim_reconcile(str(operation["operation_id"]), spiffe_id, "runner-plan", "plan")
    assert held_manifest["tenant_id"] == manifest.tenant_id
    plan_hash = "1" * 64
    with pytest.raises(ManagementConflict):
        store.record_plan(
            str(operation["operation_id"]),
            spiffe_id,
            "runner-plan",
            "00000000-0000-0000-0000-000000000000",
            int(claimed_plan["fencing_token"]),
            manifest_digest(manifest),
            plan_hash,
        )
    planned = store.record_plan(
        str(operation["operation_id"]),
        spiffe_id,
        "runner-plan",
        str(claimed_plan["claim_command_id"]),
        int(claimed_plan["fencing_token"]),
        manifest_digest(manifest),
        plan_hash,
    )
    with pytest.raises(ManagementDenied):
        store.approve_operation(
            str(operation["operation_id"]), requester, manifest_digest(manifest), plan_hash, datetime.now(timezone.utc) + timedelta(minutes=10)
        )
    store.approve_operation(
        str(operation["operation_id"]), approver, manifest_digest(manifest), plan_hash, datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    claimed_apply, _ = store.claim_reconcile(str(operation["operation_id"]), spiffe_id, "runner-apply", "apply")
    receipt = {
        "operation_id": str(operation["operation_id"]),
        "command_id": str(claimed_apply["claim_command_id"]),
        "deployment_id": manifest.deployment_id,
        "tenant_id": manifest.tenant_id,
        "fencing_token": int(claimed_apply["fencing_token"]),
        "manifest_digest": manifest_digest(manifest),
        "plan_hash": plan_hash,
        "observed_generation": 1,
        "resource_inventory": {"clusterName": "tenant-a-cluster"},
        "verification_summary": {"pulumi_result": "succeeded"},
        "provider_update_id": "pulumi-update-1",
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    receipt["signature"] = receipt_signer.sign(receipt)
    deployment = store.complete_operation(str(operation["operation_id"]), spiffe_id, "runner-apply", receipt)
    assert deployment["state"] == "active"
    assert deployment["observed_generation"] == 1

    update_value = manifest.model_dump(mode="json")
    update_value["generation"] = 2
    update_value["expected_generation"] = 1
    update = DeploymentManifest.model_validate(update_value)
    second = store.submit_operation(update, "configure", "configure-2", requester)
    claimed_second, _ = store.claim_reconcile(str(second["operation_id"]), spiffe_id, "runner-stale", "plan")
    store.cancel_operation(str(second["operation_id"]), requester)
    with pytest.raises((ManagementConflict, ManagementDenied)):
        store.record_plan(
            str(second["operation_id"]),
            spiffe_id,
            "runner-stale",
            str(claimed_second["claim_command_id"]),
            int(claimed_second["fencing_token"]),
            manifest_digest(update),
            "2" * 64,
        )
    held = store.get_deployment(manifest.deployment_id, requester)
    assert held is not None
    assert held["desired_generation"] == held["observed_generation"] == 1
