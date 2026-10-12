"""Durable T05/T06 identity expiry and substitution matrix.

This suite uses PostgreSQL as the authorization serialization point. Each
negative case starts from the same working positive control, changes one
durable authority fact, and proves the gateway lookup no longer returns an
execution context.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.agents.managed_store import ManagedRunStore

pytestmark = [pytest.mark.integration, pytest.mark.database]

ROOT = Path(__file__).resolve().parents[2]
INIT = ROOT / "infra" / "database" / "init"
DATABASE = "autobot_managed_authorization_matrix"
EXECUTION_A = "10000000-0000-4000-8000-000000000001"
EXECUTION_B = "20000000-0000-4000-8000-000000000002"
WORKLOAD_A = "spiffe://autobot.internal/ns/tenant-a/sa/worker"
WORKLOAD_B = "spiffe://autobot.internal/ns/tenant-b/sa/worker"


def _parts() -> dict[str, str]:
    return {
        "user": os.getenv("POSTGRES_USER", "deeptempo"),
        "password": os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me"),
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
    }


def _url(database: str) -> str:
    held = _parts()
    return (
        f"postgresql+psycopg2://{quote(held['user'], safe='')}:{quote(held['password'], safe='')}"
        f"@{held['host']}:{held['port']}/{database}"
    )


def _available() -> bool:
    try:
        engine = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark.append(pytest.mark.skipif(not _available(), reason="requires PostgreSQL"))


@pytest.fixture(scope="module")
def matrix_engine():
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f"DROP DATABASE IF EXISTS {DATABASE} WITH (FORCE)"))
        connection.execute(text(f"CREATE DATABASE {DATABASE}"))
    engine = create_engine(_url(DATABASE))
    with engine.begin() as connection:
        for migration in (
            "19_agent_ledger.sql",
            "21_agent_run_leases.sql",
            "31_agent_ledger_hash_chain.sql",
            "41_managed_execution.sql",
            "42_managed_workload_identity.sql",
            "45_claim_incarnation_binding.sql",
        ):
            connection.exec_driver_sql((INIT / migration).read_text(encoding="utf-8"))
    yield engine
    engine.dispose()
    with admin.connect() as connection:
        connection.execute(text(f"DROP DATABASE IF EXISTS {DATABASE} WITH (FORCE)"))
    admin.dispose()


def _seed(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("""
            TRUNCATE managed_authorization_audit, managed_invocation_reservations,
              managed_execution_budgets, managed_execution_claims, managed_runs,
              managed_admissions, managed_program_registry, managed_memberships,
              managed_deployments RESTART IDENTITY CASCADE
        """))
        for suffix, execution, workload in (
            ("a", EXECUTION_A, WORKLOAD_A),
            ("b", EXECUTION_B, WORKLOAD_B),
        ):
            tenant = f"tenant-{suffix}"
            deployment = f"deployment-{suffix}"
            incarnation = f"{1 if suffix == 'a' else 2}0000000-0000-4000-8000-00000000000{1 if suffix == 'a' else 2}"
            admission = f"{3 if suffix == 'a' else 4}0000000-0000-4000-8000-00000000000{1 if suffix == 'a' else 2}"
            run = f"{5 if suffix == 'a' else 6}0000000-0000-4000-8000-00000000000{1 if suffix == 'a' else 2}"
            connection.execute(text("""
                INSERT INTO managed_deployments
                  (deployment_id, tenant_id, incarnation, policy_version,
                   revocation_epoch, authority_public_key, status)
                VALUES (:deployment, :tenant, CAST(:incarnation AS uuid),
                        'policy-1', 0, 'qualification-key', 'active');
                INSERT INTO managed_memberships
                  (tenant_id, subject_id, issuer, roles, membership_version, status)
                VALUES (:tenant, :subject, 'https://issuer.autobot.internal',
                        '["analyst"]'::jsonb, 1, 'active');
                INSERT INTO managed_program_registry
                  (tenant_id, program_id, program_digest, artifact_signature,
                   model_config_digest, dependency_digest, status, approved_by,
                   activated_at)
                VALUES (:tenant, 'triage-v1', :program_digest, 'signature',
                        :model_digest, :dependency_digest, 'active', 'security-admin', now());
                INSERT INTO managed_admissions
                  (admission_id, tenant_id, deployment_id, subject_id, execution_id,
                   workflow_id, workflow_digest, program_id, program_digest,
                   request_digest, revocation_epoch, issued_at, expires_at, status,
                   issuer, membership_version, policy_version)
                VALUES (CAST(:admission AS uuid), :tenant, :deployment, :subject,
                        CAST(:execution AS uuid), 'triage-v1', :workflow_digest,
                        'triage-v1', :program_digest, :request_digest, 0, now(),
                        now() + interval '1 hour', 'active',
                        'https://issuer.autobot.internal', 1, 'policy-1');
                INSERT INTO managed_runs
                  (run_id, execution_id, tenant_id, deployment_id, subject_id,
                   run_kind, workflow_id, status, request, envelope)
                VALUES (CAST(:run AS uuid), CAST(:execution AS uuid), :tenant,
                        :deployment, :subject, 'investigate', 'triage-v1',
                        'running', '{}'::jsonb, '{}'::jsonb);
                INSERT INTO managed_execution_claims
                  (execution_id, worker_key_id, workload_spiffe_id, claim_token,
                   claim_version, claim_until, status, capabilities,
                   deployment_incarnation)
                VALUES (CAST(:execution AS uuid), :workload, :workload,
                        :claim, 1, now() + interval '1 hour', 'active',
                        '["get_finding"]'::jsonb, CAST(:incarnation AS uuid))
            """), {
                "tenant": tenant,
                "deployment": deployment,
                "incarnation": incarnation,
                "subject": f"user-{suffix}",
                "execution": execution,
                "admission": admission,
                "run": run,
                "workload": workload,
                "claim": f"claim-{suffix}",
                "workflow_digest": suffix * 64,
                "program_digest": suffix * 64,
                "request_digest": suffix * 64,
                "model_digest": ("c" if suffix == "a" else "d") * 64,
                "dependency_digest": ("e" if suffix == "a" else "f") * 64,
            })


@pytest.fixture()
def durable_store(matrix_engine, monkeypatch: pytest.MonkeyPatch) -> ManagedRunStore:
    _seed(matrix_engine)
    Session = sessionmaker(bind=matrix_engine)

    @contextmanager
    def sessions():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    import core.storage.connection

    monkeypatch.setattr(core.storage.connection, "get_db_session", sessions)
    return ManagedRunStore()


def test_t05_durable_authentication_membership_and_expiry_matrix(
    matrix_engine, durable_store: ManagedRunStore
) -> None:
    lookup = lambda: durable_store.authorization_context(EXECUTION_A, WORKLOAD_A, "claim-a")
    assert lookup() is not None
    assert durable_store.authorization_context(EXECUTION_A, WORKLOAD_B, "claim-a") is None
    assert durable_store.authorization_context(EXECUTION_A, WORKLOAD_A, "claim-b") is None
    assert durable_store.authorization_context(EXECUTION_B, WORKLOAD_A, "claim-a") is None

    mutations = (
        "UPDATE managed_execution_claims SET claim_until=now()-interval '1 second' WHERE execution_id=CAST(:execution AS uuid)",
        "UPDATE managed_execution_claims SET status='fenced' WHERE execution_id=CAST(:execution AS uuid)",
        "UPDATE managed_admissions SET status='revoked' WHERE execution_id=CAST(:execution AS uuid)",
        "UPDATE managed_runs SET status='cancelled' WHERE execution_id=CAST(:execution AS uuid)",
        "UPDATE managed_deployments SET status='suspended' WHERE deployment_id='deployment-a'",
        "UPDATE managed_memberships SET status='revoked' WHERE tenant_id='tenant-a'",
        "UPDATE managed_memberships SET membership_version=2 WHERE tenant_id='tenant-a'",
        "UPDATE managed_deployments SET revocation_epoch=1 WHERE deployment_id='deployment-a'",
        "UPDATE managed_program_registry SET status='revoked', revoked_at=now(), activated_at=NULL WHERE tenant_id='tenant-a'",
    )
    for statement in mutations:
        _seed(matrix_engine)
        assert lookup() is not None
        with matrix_engine.begin() as connection:
            connection.execute(text(statement), {"execution": EXECUTION_A})
        assert lookup() is None, statement


def test_t05_reprovisioned_deployment_rejects_old_durable_claim(
    matrix_engine, durable_store: ManagedRunStore
) -> None:
    before = durable_store.authorization_context(EXECUTION_A, WORKLOAD_A, "claim-a")
    assert str(before["deployment_incarnation"]) == "10000000-0000-4000-8000-000000000001"
    with matrix_engine.begin() as connection:
        connection.execute(text("""
            UPDATE managed_deployments
            SET incarnation='90000000-0000-4000-8000-000000000009'
            WHERE deployment_id='deployment-a'
        """))
    after = durable_store.authorization_context(EXECUTION_A, WORKLOAD_A, "claim-a")
    assert after is None
