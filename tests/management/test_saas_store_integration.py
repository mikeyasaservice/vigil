from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import psycopg2
import pytest
from services.management.saas_auth import CustomerIdentity
from services.management.store import ManagementConflict, ManagementDenied, ManagementStore

ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = os.getenv("PHASE3_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="PHASE3_TEST_DATABASE_URL is not configured"
)


@pytest.fixture()
def saas_state() -> ManagementStore:
    assert DATABASE_URL is not None
    connection = psycopg2.connect(DATABASE_URL)
    connection.autocommit = True
    with connection.cursor() as cursor:
        for migration in (
            "001_management_plane.sql",
            "002_binding_execution_profile.sql",
            "003_shared_saas_control.sql",
        ):
            cursor.execute((ROOT / "infra/management/database" / migration).read_text())
        cursor.execute(
            """
            TRUNCATE management_saas_audit, management_usage_reservations,
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
            INSERT INTO management_organizations (organization_id, display_name)
            VALUES ('organization-a', 'Organization A'), ('organization-b', 'Organization B');
            INSERT INTO management_organization_tenants (organization_id, tenant_id)
            VALUES ('organization-a', 'tenant-a'), ('organization-b', 'tenant-b');
            INSERT INTO management_account_bindings
              (binding_ref, tenant_id, deployment_id, provider, execution_profile,
               account_id, role_arn, region, network_binding_ref, state_binding_ref,
               binding_digest, external_id_secret_ref, reconciler_spiffe_id, receipt_public_key)
            VALUES
              ('local:binding-a', 'tenant-a', 'deployment-a', 'aws', 'localstack',
               '000000000000', '', 'us-east-1', 'local:network-a', 'local:state-a',
               repeat('a', 64), 'local:external-a', 'spiffe://vigil.io/reconciler/a', 'key-a'),
              ('local:binding-b', 'tenant-b', 'deployment-b', 'aws', 'localstack',
               '000000000000', '', 'us-east-1', 'local:network-b', 'local:state-b',
               repeat('b', 64), 'local:external-b', 'spiffe://vigil.io/reconciler/b', 'key-b');
            INSERT INTO management_deployments
              (deployment_id, tenant_id, binding_ref, incarnation, desired_generation,
               observed_generation, state)
            VALUES
              ('deployment-a', 'tenant-a', 'local:binding-a', '11111111-1111-4111-8111-111111111111', 1, 1, 'active'),
              ('deployment-b', 'tenant-b', 'local:binding-b', '22222222-2222-4222-8222-222222222222', 1, 1, 'active');
            INSERT INTO management_saas_cells (cell_id, region, route_ref)
            VALUES ('cell-us-east-1', 'us-east-1', 'local:cell-us-east-1-router');
            INSERT INTO management_saas_tenant_bindings
              (tenant_id, deployment_id, cell_id, data_plane_spiffe_id)
            VALUES
              ('tenant-a', 'deployment-a', 'cell-us-east-1', 'spiffe://vigil.io/data-plane/a'),
              ('tenant-b', 'deployment-b', 'cell-us-east-1', 'spiffe://vigil.io/data-plane/b');
            INSERT INTO management_tenant_memberships
              (issuer, subject_id, tenant_id, role, membership_version)
            VALUES
              ('https://customers.example', 'user-a', 'tenant-a', 'analyst', 1),
              ('https://customers.example', 'user-b', 'tenant-b', 'analyst', 1);
            INSERT INTO management_quota_policies
              (tenant_id, dimension, hard_limit, window_seconds, policy_version)
            VALUES ('tenant-a', 'model_tokens', 100, 3600, 1),
                   ('tenant-b', 'model_tokens', 100, 3600, 1);
            """
        )
    connection.close()
    return ManagementStore(DATABASE_URL)


def test_membership_and_route_do_not_disclose_foreign_tenant(saas_state: ManagementStore) -> None:
    user_a = CustomerIdentity("https://customers.example", "user-a", "session-a")
    contexts = saas_state.list_saas_contexts(user_a)
    assert [row["tenant_id"] for row in contexts] == ["tenant-a"]
    route = saas_state.resolve_saas_route("tenant-a", user_a)
    assert route["deployment_id"] == "deployment-a"
    with pytest.raises(ManagementDenied):
        saas_state.resolve_saas_route("tenant-b", user_a)
    saas_state.record_route_ticket(str(uuid.uuid4()), route, user_a, route_expiry())
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE management_tenant_memberships SET membership_version = 2 WHERE tenant_id = 'tenant-a'"
            )
    with pytest.raises(ManagementDenied):
        saas_state.record_route_ticket(str(uuid.uuid4()), route, user_a, route_expiry())


def route_expiry():
    from datetime import datetime, timedelta, timezone

    return datetime.now(timezone.utc) + timedelta(seconds=60)


def test_quota_is_workload_bound_idempotent_and_tenant_isolated(
    saas_state: ManagementStore,
) -> None:
    digest = "1" * 64
    first = saas_state.reserve_quota(
        "deployment-a", "spiffe://vigil.io/data-plane/a", "call-1", digest, "model_tokens", 40
    )
    replay = saas_state.reserve_quota(
        "deployment-a", "spiffe://vigil.io/data-plane/a", "call-1", digest, "model_tokens", 40
    )
    assert replay["reservation_id"] == first["reservation_id"]
    with pytest.raises(ManagementConflict):
        saas_state.reserve_quota(
            "deployment-a", "spiffe://vigil.io/data-plane/a", "call-1", "2" * 64, "model_tokens", 40
        )
    with pytest.raises(ManagementDenied):
        saas_state.reserve_quota(
            "deployment-b", "spiffe://vigil.io/data-plane/a", "foreign", digest, "model_tokens", 1
        )
    bounded = saas_state.reserve_quota(
        "deployment-a",
        "spiffe://vigil.io/data-plane/a",
        "call-bounded",
        "3" * 64,
        "model_tokens",
        10,
    )
    with pytest.raises(ManagementDenied):
        saas_state.commit_quota(
            "deployment-a",
            "spiffe://vigil.io/data-plane/a",
            str(bounded["reservation_id"]),
            "3" * 64,
            11,
        )
    committed = saas_state.commit_quota(
        "deployment-a", "spiffe://vigil.io/data-plane/a", str(first["reservation_id"]), digest, 31
    )
    assert committed["status"] == "committed"
    assert DATABASE_URL is not None
    with psycopg2.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT action FROM management_saas_audit WHERE tenant_id = 'tenant-a' ORDER BY audit_id"
            )
            assert [row[0] for row in cursor.fetchall()] == [
                "quota.reserve",
                "quota.reserve",
                "quota.commit",
            ]
    usage = saas_state.list_usage(
        "tenant-a", CustomerIdentity("https://customers.example", "user-a", "session-a")
    )
    assert usage[0]["committed_amount"] == 31
    with pytest.raises(ManagementDenied):
        saas_state.list_usage(
            "tenant-b", CustomerIdentity("https://customers.example", "user-a", "session-a")
        )


def test_concurrent_quota_reservations_cannot_overspend(saas_state: ManagementStore) -> None:
    outcomes: list[str] = []
    lock = threading.Lock()

    def reserve(invocation: str) -> None:
        try:
            saas_state.reserve_quota(
                "deployment-a",
                "spiffe://vigil.io/data-plane/a",
                invocation,
                ("a" if invocation == "concurrent-a" else "b") * 64,
                "model_tokens",
                60,
            )
            result = "allowed"
        except ManagementDenied:
            result = "denied"
        with lock:
            outcomes.append(result)

    threads = [
        threading.Thread(target=reserve, args=(name,)) for name in ("concurrent-a", "concurrent-b")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["allowed", "denied"]
    tenant_b = saas_state.reserve_quota(
        "deployment-b",
        "spiffe://vigil.io/data-plane/b",
        "tenant-b-capacity",
        "c" * 64,
        "model_tokens",
        100,
    )
    assert tenant_b["reserved_amount"] == 100
