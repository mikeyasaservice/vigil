from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

import core.agents.dspy_lifecycle_store as lifecycle_module
from core.agents.dspy_lifecycle_store import DSPyLifecycleStore
from core.agents.managed_execution import ManagedSecurityError

DATABASE_URL = os.getenv("DSPY_LIFECYCLE_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DSPy lifecycle PostgreSQL URL is not configured"
)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def store(monkeypatch):
    engine = create_engine(DATABASE_URL)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
        connection.execute(text("CREATE TABLE agent_events(id bigint)"))
        connection.execute(
            text(
                "CREATE TABLE agent_run_leases(owner text, claim_until timestamptz, run_kind text)"
            )
        )
    raw = engine.raw_connection()
    try:
        cursor = raw.cursor()
        for name in (
            "41_managed_execution.sql",
            "42_managed_workload_identity.sql",
            "43_dspy_optimization_lifecycle.sql",
        ):
            cursor.execute((ROOT / "infra/database/init" / name).read_text())
        raw.commit()
    finally:
        raw.close()

    @contextmanager
    def local_unit_of_work():
        session = Session(engine)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(lifecycle_module, "unit_of_work", local_unit_of_work)
    with engine.begin() as connection:
        connection.execute(text("""
            INSERT INTO managed_deployments
              (deployment_id, tenant_id, incarnation, policy_version, authority_public_key)
            VALUES ('deployment-a', 'tenant-a', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'policy-1', 'authority')
        """))
        connection.execute(
            text("""
            INSERT INTO managed_program_registry
              (tenant_id, program_id, program_digest, artifact_signature,
               model_config_digest, dependency_digest, status, approved_by, activated_at)
            VALUES ('tenant-a', 'triage-dspy-v1', :digest, 'base-signature',
                    :model, :dependencies, 'active', 'release-approver', now())
        """),
            {
                "digest": "sha256:" + "1" * 64,
                "model": "sha256:" + "2" * 64,
                "dependencies": "sha256:" + "3" * 64,
            },
        )
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('vigil_reasoner', "
                "'managed_dspy_evaluations', 'UPDATE')"
            )
        ).scalar_one()
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('vigil_reasoner', "
                "'managed_dspy_lifecycle_audit', 'INSERT')"
            )
        ).scalar_one()
    yield DSPyLifecycleStore(), engine
    engine.dispose()


def test_complete_promotion_and_two_person_rollback(store) -> None:
    repository, engine = store
    dataset_id = str(uuid.uuid4())
    repository.register_dataset(
        dataset_id=dataset_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        name="synthetic",
        version=1,
        object_ref="local:datasets/synthetic.json",
        content_digest="sha256:" + "4" * 64,
        schema_digest="sha256:" + "5" * 64,
        split_manifest={"train": 1, "development": 1, "holdout": 1, "safety": 1},
        use_purpose="qualification",
        sensitivity="synthetic",
        retention_policy_ref="local:retention/default",
        access_policy_ref="local:access/reasoner",
        actor="requester",
    )
    optimization_id = str(uuid.uuid4())
    repository.create_optimization(
        optimization_id=optimization_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        dataset_id=dataset_id,
        base_program_id="triage-dspy-v1",
        base_program_digest="sha256:" + "1" * 64,
        optimizer_name="miprov2",
        optimizer_config={"auto": "light"},
        optimizer_config_digest="sha256:" + "6" * 64,
        model_config_digest="sha256:" + "7" * 64,
        dependency_digest="sha256:" + "8" * 64,
        seed=9,
        max_tokens=1000,
        max_cost_microusd=1000,
        lineage_classification="synthetic",
        actor="requester",
    )
    candidate_digest = "sha256:" + "9" * 64
    repository.complete_optimization(
        optimization_id=optimization_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        candidate_artifact_ref="local:programs/candidate.json",
        candidate_digest=candidate_digest,
        candidate_signature="candidate-signature",
        used_tokens=100,
        used_cost_microusd=100,
        actor="reasoner",
    )
    evaluation_ids = {}
    for split in ("holdout", "safety"):
        evaluation_id = str(uuid.uuid4())
        evaluation_ids[split] = evaluation_id
        repository.create_evaluation(
            evaluation_id=evaluation_id,
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            dataset_id=dataset_id,
            program_id="triage-dspy-v1",
            program_digest=candidate_digest,
            model_config_digest="sha256:" + "7" * 64,
            evaluator_digest="sha256:" + "a" * 64,
            metric_contract_digest="sha256:" + "b" * 64,
            split_name=split,
            seed=9,
            thresholds={"minimum_pass_rate": 1},
            execution_location="tenant-local",
            max_tokens=1000,
            max_cost_microusd=1000,
            actor="requester",
        )
        repository.complete_evaluation(
            evaluation_id=evaluation_id,
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            metrics={"pass_rate": 1},
            failures=[],
            passed=True,
            used_tokens=10,
            used_cost_microusd=10,
            local_trace_ref=f"local:traces/{split}",
            actor="reasoner",
        )
    staged_promotion_id = str(uuid.uuid4())
    staged_request_digest = "sha256:" + "f" * 64
    repository.request_promotion(
        promotion_id=staged_promotion_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        optimization_id=optimization_id,
        evaluation_id=evaluation_ids["holdout"],
        target_stage="staged",
        policy_version="policy-1",
        request_digest=staged_request_digest,
        actor="requester",
    )
    repository.approve_promotion(
        promotion_id=staged_promotion_id,
        tenant_id="tenant-a",
        approver="approver",
        request_digest=staged_request_digest,
        approval_signature="staging-signature",
    )
    staged = repository.stage(
        promotion_id=staged_promotion_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        actor="operator",
        sign=lambda _: "approved-artifact-signature",
    )
    assert staged["status"] == "approved"
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM managed_dspy_deployment_bindings")
            ).scalar_one()
            == 0
        )

    promotion_id = str(uuid.uuid4())
    request_digest = "sha256:" + "c" * 64
    repository.request_promotion(
        promotion_id=promotion_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        optimization_id=optimization_id,
        evaluation_id=evaluation_ids["holdout"],
        target_stage="active",
        policy_version="policy-1",
        request_digest=request_digest,
        actor="requester",
    )
    repository.approve_promotion(
        promotion_id=promotion_id,
        tenant_id="tenant-a",
        approver="approver",
        request_digest=request_digest,
        approval_signature="promotion-signature",
    )
    activated = repository.activate(
        promotion_id=promotion_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        actor="operator",
        sign=lambda _: "active-signature",
    )
    assert activated["active_program_digest"] == candidate_digest
    assert activated["previous_program_digest"] == "sha256:" + "1" * 64

    rollback_id = str(uuid.uuid4())
    rollback_digest = "sha256:" + "d" * 64
    repository.request_rollback(
        rollback_id=rollback_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        program_id="triage-dspy-v1",
        target_program_digest="sha256:" + "1" * 64,
        policy_version="policy-1",
        request_digest=rollback_digest,
        actor="requester",
    )
    with pytest.raises(ManagedSecurityError, match="self-approved"):
        repository.approve_rollback(
            rollback_id=rollback_id,
            tenant_id="tenant-a",
            approver="requester",
            request_digest=rollback_digest,
            approval_signature="bad",
        )
    repository.approve_rollback(
        rollback_id=rollback_id,
        tenant_id="tenant-a",
        approver="approver",
        request_digest=rollback_digest,
        approval_signature="rollback-signature",
    )
    rolled_back = repository.apply_rollback(
        rollback_id=rollback_id,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        actor="operator",
        sign=lambda _: "rollback-active-signature",
    )
    assert rolled_back["active_program_digest"] == "sha256:" + "1" * 64
    assert rolled_back["rollout_generation"] == 2
    with engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT status FROM managed_dspy_rollbacks WHERE rollback_id = CAST(:id AS uuid)"
                ),
                {"id": rollback_id},
            ).scalar_one()
            == "applied"
        )

    with engine.begin() as connection:
        connection.execute(
            text("""
                UPDATE managed_program_registry
                   SET status = 'revoked', revoked_at = now()
                 WHERE tenant_id = 'tenant-a' AND program_id = 'triage-dspy-v1'
                   AND program_digest = :digest
            """),
            {"digest": candidate_digest},
        )
    with pytest.raises(ManagedSecurityError, match="unavailable or revoked"):
        repository.request_rollback(
            rollback_id=str(uuid.uuid4()),
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            program_id="triage-dspy-v1",
            target_program_digest=candidate_digest,
            policy_version="policy-1",
            request_digest="sha256:" + "e" * 64,
            actor="requester",
        )
