"""Durable tenant-local repository for the DSPy optimization lifecycle."""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Mapping

from sqlalchemy import text

from core.agents.managed_execution import ManagedSecurityError
from core.agents.managed_store import program_registry_payload
from core.storage.unit_of_work import unit_of_work


class DSPyLifecycleStore:
    @staticmethod
    def _audit(
        session: Any,
        *,
        tenant_id: str,
        deployment_id: str,
        actor: str,
        event_type: str,
        aggregate_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        session.execute(
            text("""
            INSERT INTO managed_dspy_lifecycle_audit
              (tenant_id, deployment_id, actor_subject_id, event_type, aggregate_id, payload)
            VALUES (:tenant_id, :deployment_id, :actor, :event_type,
                    CAST(:aggregate_id AS uuid), CAST(:payload AS jsonb))
        """),
            {
                "tenant_id": tenant_id,
                "deployment_id": deployment_id,
                "actor": actor,
                "event_type": event_type,
                "aggregate_id": aggregate_id,
                "payload": json.dumps(
                    dict(payload), sort_keys=True, separators=(",", ":")
                ),
            },
        )

    def register_dataset(
        self,
        *,
        dataset_id: str,
        tenant_id: str,
        deployment_id: str,
        name: str,
        version: int,
        object_ref: str,
        content_digest: str,
        schema_digest: str,
        split_manifest: Mapping[str, int],
        use_purpose: str,
        sensitivity: str,
        retention_policy_ref: str,
        access_policy_ref: str,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            deployment = session.execute(
                text("""
                SELECT 1 FROM managed_deployments
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                   AND status = 'active'
                 FOR SHARE
            """),
                {"tenant_id": tenant_id, "deployment_id": deployment_id},
            ).one_or_none()
            if deployment is None:
                raise ManagedSecurityError("dataset deployment binding is not active")
            row = (
                session.execute(
                    text("""
                INSERT INTO managed_dspy_datasets
                  (dataset_id, tenant_id, deployment_id, name, version, object_ref,
                   content_digest, schema_digest, split_manifest, use_purpose,
                   sensitivity, retention_policy_ref, access_policy_ref, created_by)
                VALUES (CAST(:dataset_id AS uuid), :tenant_id, :deployment_id, :name,
                        :version, :object_ref, :content_digest, :schema_digest,
                        CAST(:split_manifest AS jsonb), :use_purpose, :sensitivity,
                        :retention_policy_ref, :access_policy_ref, :actor)
                ON CONFLICT (tenant_id, name, version) DO NOTHING
                RETURNING *
            """),
                    {
                        "dataset_id": dataset_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "name": name,
                        "version": version,
                        "object_ref": object_ref,
                        "content_digest": content_digest,
                        "schema_digest": schema_digest,
                        "split_manifest": json.dumps(
                            dict(split_manifest), sort_keys=True
                        ),
                        "use_purpose": use_purpose,
                        "sensitivity": sensitivity,
                        "retention_policy_ref": retention_policy_ref,
                        "access_policy_ref": access_policy_ref,
                        "actor": actor,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                existing = (
                    session.execute(
                        text("""
                    SELECT * FROM managed_dspy_datasets
                     WHERE tenant_id = :tenant_id AND name = :name AND version = :version
                """),
                        {"tenant_id": tenant_id, "name": name, "version": version},
                    )
                    .mappings()
                    .one()
                )
                if any(
                    str(existing[key]) != str(value)
                    for key, value in {
                        "dataset_id": uuid.UUID(dataset_id),
                        "deployment_id": deployment_id,
                        "object_ref": object_ref,
                        "content_digest": content_digest,
                        "schema_digest": schema_digest,
                    }.items()
                ):
                    raise ManagedSecurityError(
                        "dataset version already identifies different content"
                    )
                return dict(existing)
            held = dict(row)
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.dataset.locked",
                aggregate_id=dataset_id,
                payload={
                    "content_digest": content_digest,
                    "schema_digest": schema_digest,
                },
            )
            return held

    def create_evaluation(
        self,
        *,
        evaluation_id: str,
        tenant_id: str,
        deployment_id: str,
        dataset_id: str,
        program_id: str,
        program_digest: str,
        model_config_digest: str,
        evaluator_digest: str,
        metric_contract_digest: str,
        split_name: str,
        seed: int,
        thresholds: Mapping[str, float],
        execution_location: str,
        max_tokens: int,
        max_cost_microusd: int,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            dataset = (
                session.execute(
                    text("""
                SELECT content_digest FROM managed_dspy_datasets
                 WHERE dataset_id = CAST(:dataset_id AS uuid) AND tenant_id = :tenant_id
                   AND deployment_id = :deployment_id AND status = 'locked'
                 FOR SHARE
            """),
                    {
                        "dataset_id": dataset_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if dataset is None:
                raise ManagedSecurityError("evaluation dataset is unavailable")
            candidate = session.execute(
                text("""
                SELECT 1 FROM managed_dspy_optimizations
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                   AND base_program_id = :program_id AND candidate_digest = :program_digest
                   AND status = 'candidate'
            """),
                {
                    "tenant_id": tenant_id,
                    "deployment_id": deployment_id,
                    "program_id": program_id,
                    "program_digest": program_digest,
                },
            ).one_or_none()
            registry = session.execute(
                text("""
                SELECT 1 FROM managed_program_registry
                 WHERE tenant_id = :tenant_id AND program_id = :program_id
                   AND program_digest = :program_digest AND status IN ('approved', 'active')
            """),
                {
                    "tenant_id": tenant_id,
                    "program_id": program_id,
                    "program_digest": program_digest,
                },
            ).one_or_none()
            if candidate is None and registry is None:
                raise ManagedSecurityError(
                    "evaluation program is not an owned approved artifact"
                )
            row = (
                session.execute(
                    text("""
                INSERT INTO managed_dspy_evaluations
                  (evaluation_id, tenant_id, deployment_id, dataset_id, dataset_digest,
                   program_id, program_digest, model_config_digest, evaluator_digest,
                   metric_contract_digest, split_name, seed, thresholds,
                   execution_location, max_tokens, max_cost_microusd, requested_by)
                VALUES (CAST(:evaluation_id AS uuid), :tenant_id, :deployment_id,
                        CAST(:dataset_id AS uuid), :dataset_digest, :program_id,
                        :program_digest, :model_config_digest, :evaluator_digest,
                        :metric_contract_digest, :split_name, :seed,
                        CAST(:thresholds AS jsonb), :execution_location, :max_tokens,
                        :max_cost_microusd, :actor)
                RETURNING *
            """),
                    {
                        "evaluation_id": evaluation_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "dataset_id": dataset_id,
                        "dataset_digest": dataset["content_digest"],
                        "program_id": program_id,
                        "program_digest": program_digest,
                        "model_config_digest": model_config_digest,
                        "evaluator_digest": evaluator_digest,
                        "metric_contract_digest": metric_contract_digest,
                        "split_name": split_name,
                        "seed": seed,
                        "thresholds": json.dumps(dict(thresholds), sort_keys=True),
                        "execution_location": execution_location,
                        "max_tokens": max_tokens,
                        "max_cost_microusd": max_cost_microusd,
                        "actor": actor,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.evaluation.queued",
                aggregate_id=evaluation_id,
                payload={
                    "dataset_digest": dataset["content_digest"],
                    "program_digest": program_digest,
                    "split_name": split_name,
                },
            )
            return dict(row)

    def complete_evaluation(
        self,
        *,
        evaluation_id: str,
        tenant_id: str,
        deployment_id: str,
        metrics: Mapping[str, int | float],
        failures: list[Mapping[str, str]],
        passed: bool,
        used_tokens: int,
        used_cost_microusd: int,
        local_trace_ref: str,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            row = (
                session.execute(
                    text("""
                UPDATE managed_dspy_evaluations
                   SET status = :status, metrics = CAST(:metrics AS jsonb),
                       failures = CAST(:failures AS jsonb), used_tokens = :used_tokens,
                       used_cost_microusd = :used_cost, local_trace_ref = :trace,
                       started_at = COALESCE(started_at, now()), completed_at = now()
                 WHERE evaluation_id = CAST(:evaluation_id AS uuid)
                   AND tenant_id = :tenant_id AND deployment_id = :deployment_id
                   AND status IN ('queued', 'running')
                   AND :used_tokens <= max_tokens AND :used_cost <= max_cost_microusd
                RETURNING *
            """),
                    {
                        "status": "passed" if passed else "failed",
                        "metrics": json.dumps(dict(metrics), sort_keys=True),
                        "failures": json.dumps(failures, sort_keys=True),
                        "used_tokens": used_tokens,
                        "used_cost": used_cost_microusd,
                        "trace": local_trace_ref,
                        "evaluation_id": evaluation_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ManagedSecurityError(
                    "evaluation completion is stale, foreign or over budget"
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type=f"dspy.evaluation.{row['status']}",
                aggregate_id=evaluation_id,
                payload={
                    "metrics": dict(metrics),
                    "used_tokens": used_tokens,
                    "used_cost_microusd": used_cost_microusd,
                },
            )
            return dict(row)

    def create_optimization(
        self,
        *,
        optimization_id: str,
        tenant_id: str,
        deployment_id: str,
        dataset_id: str,
        base_program_id: str,
        base_program_digest: str,
        optimizer_name: str,
        optimizer_config: Mapping[str, Any],
        optimizer_config_digest: str,
        model_config_digest: str,
        dependency_digest: str,
        seed: int,
        max_tokens: int,
        max_cost_microusd: int,
        lineage_classification: str,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            source = (
                session.execute(
                    text("""
                SELECT d.content_digest
                  FROM managed_dspy_datasets d
                  JOIN managed_program_registry p ON p.tenant_id = d.tenant_id
                 WHERE d.dataset_id = CAST(:dataset_id AS uuid)
                   AND d.tenant_id = :tenant_id AND d.deployment_id = :deployment_id
                   AND d.status = 'locked' AND p.program_id = :program_id
                   AND p.program_digest = :program_digest AND p.status IN ('approved', 'active')
                 FOR SHARE OF d, p
            """),
                    {
                        "dataset_id": dataset_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": base_program_id,
                        "program_digest": base_program_digest,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if source is None:
                raise ManagedSecurityError("optimization source is unavailable")
            row = (
                session.execute(
                    text("""
                INSERT INTO managed_dspy_optimizations
                  (optimization_id, tenant_id, deployment_id, dataset_id, dataset_digest,
                   base_program_id, base_program_digest, optimizer_name, optimizer_config,
                   optimizer_config_digest, model_config_digest, dependency_digest, seed,
                   max_tokens, max_cost_microusd, lineage_classification, requested_by)
                VALUES (CAST(:optimization_id AS uuid), :tenant_id, :deployment_id,
                        CAST(:dataset_id AS uuid), :dataset_digest, :program_id,
                        :program_digest, :optimizer_name, CAST(:optimizer_config AS jsonb),
                        :optimizer_config_digest, :model_config_digest, :dependency_digest,
                        :seed, :max_tokens, :max_cost, :lineage, :actor)
                RETURNING *
            """),
                    {
                        "optimization_id": optimization_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "dataset_id": dataset_id,
                        "dataset_digest": source["content_digest"],
                        "program_id": base_program_id,
                        "program_digest": base_program_digest,
                        "optimizer_name": optimizer_name,
                        "optimizer_config": json.dumps(
                            dict(optimizer_config), sort_keys=True
                        ),
                        "optimizer_config_digest": optimizer_config_digest,
                        "model_config_digest": model_config_digest,
                        "dependency_digest": dependency_digest,
                        "seed": seed,
                        "max_tokens": max_tokens,
                        "max_cost": max_cost_microusd,
                        "lineage": lineage_classification,
                        "actor": actor,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.optimization.queued",
                aggregate_id=optimization_id,
                payload={
                    "dataset_digest": source["content_digest"],
                    "base_program_digest": base_program_digest,
                    "optimizer_config_digest": optimizer_config_digest,
                },
            )
            return dict(row)

    def complete_optimization(
        self,
        *,
        optimization_id: str,
        tenant_id: str,
        deployment_id: str,
        candidate_artifact_ref: str,
        candidate_digest: str,
        candidate_signature: str,
        used_tokens: int,
        used_cost_microusd: int,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            row = (
                session.execute(
                    text("""
                UPDATE managed_dspy_optimizations
                   SET status = 'candidate', candidate_artifact_ref = :artifact_ref,
                       candidate_digest = :candidate_digest,
                       candidate_signature = :candidate_signature,
                       used_tokens = :used_tokens, used_cost_microusd = :used_cost,
                       started_at = COALESCE(started_at, now()), completed_at = now()
                 WHERE optimization_id = CAST(:optimization_id AS uuid)
                   AND tenant_id = :tenant_id AND deployment_id = :deployment_id
                   AND status IN ('queued', 'running')
                   AND :used_tokens <= max_tokens AND :used_cost <= max_cost_microusd
                RETURNING *
            """),
                    {
                        "artifact_ref": candidate_artifact_ref,
                        "candidate_digest": candidate_digest,
                        "candidate_signature": candidate_signature,
                        "used_tokens": used_tokens,
                        "used_cost": used_cost_microusd,
                        "optimization_id": optimization_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ManagedSecurityError(
                    "optimization completion is stale, foreign or over budget"
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.optimization.candidate",
                aggregate_id=optimization_id,
                payload={"candidate_digest": candidate_digest},
            )
            return dict(row)

    def request_promotion(
        self,
        *,
        promotion_id: str,
        tenant_id: str,
        deployment_id: str,
        optimization_id: str,
        evaluation_id: str,
        target_stage: str,
        policy_version: str,
        request_digest: str,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            source = (
                session.execute(
                    text("""
                SELECT o.base_program_id AS program_id, o.candidate_digest,
                       o.dataset_digest, e.split_name
                  FROM managed_dspy_optimizations o
                  JOIN managed_dspy_evaluations e
                    ON e.tenant_id = o.tenant_id AND e.deployment_id = o.deployment_id
                   AND e.dataset_digest = o.dataset_digest
                   AND e.program_id = o.base_program_id
                   AND e.program_digest = o.candidate_digest
                 WHERE o.optimization_id = CAST(:optimization_id AS uuid)
                   AND e.evaluation_id = CAST(:evaluation_id AS uuid)
                   AND o.tenant_id = :tenant_id AND o.deployment_id = :deployment_id
                   AND o.status = 'candidate' AND e.status = 'passed'
                   AND e.split_name = 'holdout'
                 FOR SHARE OF o, e
            """),
                    {
                        "optimization_id": optimization_id,
                        "evaluation_id": evaluation_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if source is None:
                raise ManagedSecurityError(
                    "promotion requires the candidate's passing holdout evaluation"
                )
            safety = session.execute(
                text("""
                SELECT 1 FROM managed_dspy_evaluations
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                   AND dataset_digest = :dataset_digest AND program_id = :program_id
                   AND program_digest = :program_digest AND split_name = 'safety'
                   AND status = 'passed'
            """),
                {
                    "tenant_id": tenant_id,
                    "deployment_id": deployment_id,
                    "dataset_digest": source["dataset_digest"],
                    "program_id": source["program_id"],
                    "program_digest": source["candidate_digest"],
                },
            ).one_or_none()
            if safety is None:
                raise ManagedSecurityError(
                    "promotion requires a passing safety evaluation"
                )
            row = (
                session.execute(
                    text("""
                INSERT INTO managed_dspy_promotions
                  (promotion_id, tenant_id, deployment_id, optimization_id,
                   evaluation_id, program_id, candidate_digest, target_stage,
                   policy_version, request_digest, requested_by)
                VALUES (CAST(:promotion_id AS uuid), :tenant_id, :deployment_id,
                        CAST(:optimization_id AS uuid), CAST(:evaluation_id AS uuid),
                        :program_id, :candidate_digest, :target_stage, :policy_version,
                        :request_digest, :actor)
                RETURNING *
            """),
                    {
                        "promotion_id": promotion_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "optimization_id": optimization_id,
                        "evaluation_id": evaluation_id,
                        "program_id": source["program_id"],
                        "candidate_digest": source["candidate_digest"],
                        "target_stage": target_stage,
                        "policy_version": policy_version,
                        "request_digest": request_digest,
                        "actor": actor,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.promotion.requested",
                aggregate_id=promotion_id,
                payload={
                    "candidate_digest": source["candidate_digest"],
                    "target_stage": target_stage,
                },
            )
            return dict(row)

    def approve_promotion(
        self,
        *,
        promotion_id: str,
        tenant_id: str,
        approver: str,
        request_digest: str,
        approval_signature: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            row = (
                session.execute(
                    text("""
                UPDATE managed_dspy_promotions
                   SET status = 'approved', approved_by = :approver,
                       approval_signature = :signature, resolved_at = now()
                 WHERE promotion_id = CAST(:promotion_id AS uuid)
                   AND tenant_id = :tenant_id AND status = 'pending'
                   AND requested_by <> :approver AND request_digest = :request_digest
                RETURNING *
            """),
                    {
                        "promotion_id": promotion_id,
                        "tenant_id": tenant_id,
                        "approver": approver,
                        "signature": approval_signature,
                        "request_digest": request_digest,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ManagedSecurityError(
                    "promotion approval is stale, altered, foreign or self-approved"
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=str(row["deployment_id"]),
                actor=approver,
                event_type="dspy.promotion.approved",
                aggregate_id=promotion_id,
                payload={
                    "request_digest": request_digest,
                    "candidate_digest": row["candidate_digest"],
                },
            )
            return dict(row)

    def activate(
        self,
        *,
        promotion_id: str,
        tenant_id: str,
        deployment_id: str,
        actor: str,
        sign: Callable[[Mapping[str, Any]], str],
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            promotion = (
                session.execute(
                    text("""
                SELECT p.*, o.candidate_artifact_ref, o.lineage_classification,
                       o.model_config_digest, o.dependency_digest
                  FROM managed_dspy_promotions p
                  JOIN managed_dspy_optimizations o ON o.optimization_id = p.optimization_id
                 WHERE p.promotion_id = CAST(:promotion_id AS uuid)
                   AND p.tenant_id = :tenant_id AND p.deployment_id = :deployment_id
                   AND p.status = 'approved' AND p.target_stage = 'active'
                   AND o.status = 'candidate'
                 FOR UPDATE OF p, o
            """),
                    {
                        "promotion_id": promotion_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if promotion is None:
                raise ManagedSecurityError("approved promotion is unavailable")
            revoked = session.execute(
                text("""
                SELECT 1 FROM managed_program_registry
                 WHERE tenant_id = :tenant_id AND program_id = :program_id
                   AND program_digest = :digest AND status = 'revoked'
            """),
                {
                    "tenant_id": tenant_id,
                    "program_id": promotion["program_id"],
                    "digest": promotion["candidate_digest"],
                },
            ).one_or_none()
            if revoked is not None:
                raise ManagedSecurityError("revoked program cannot be activated")
            registry_record = {
                "tenant_id": tenant_id,
                "program_id": str(promotion["program_id"]),
                "program_digest": str(promotion["candidate_digest"]),
                "model_config_digest": str(promotion["model_config_digest"]),
                "dependency_digest": str(promotion["dependency_digest"]),
                "status": "active",
            }
            artifact_signature = sign(program_registry_payload(registry_record))
            previous = session.execute(
                text("""
                SELECT program_digest FROM managed_program_registry
                 WHERE tenant_id = :tenant_id AND program_id = :program_id
                   AND status = 'active' FOR UPDATE
            """),
                {"tenant_id": tenant_id, "program_id": promotion["program_id"]},
            ).one_or_none()
            session.execute(
                text("""
                UPDATE managed_program_registry SET status = 'approved', activated_at = NULL
                 WHERE tenant_id = :tenant_id AND program_id = :program_id AND status = 'active'
            """),
                {"tenant_id": tenant_id, "program_id": promotion["program_id"]},
            )
            registered = session.execute(
                text("""
                INSERT INTO managed_program_registry
                  (tenant_id, program_id, program_digest, artifact_signature,
                   model_config_digest, dependency_digest, status, approved_by,
                   approved_at, activated_at, source_optimization_id,
                   source_evaluation_id, artifact_ref, semantic_version,
                   lineage_classification)
                VALUES (:tenant_id, :program_id, :digest, :signature,
                        :model_config_digest, :dependency_digest, 'active', :actor,
                        now(), now(), :optimization_id, :evaluation_id, :artifact_ref,
                        :semantic_version, :lineage)
                ON CONFLICT (tenant_id, program_id, program_digest) DO UPDATE
                  SET artifact_signature = EXCLUDED.artifact_signature,
                      model_config_digest = EXCLUDED.model_config_digest,
                      dependency_digest = EXCLUDED.dependency_digest,
                      status = 'active', activated_at = now(), revoked_at = NULL,
                      source_optimization_id = EXCLUDED.source_optimization_id,
                      source_evaluation_id = EXCLUDED.source_evaluation_id,
                      artifact_ref = EXCLUDED.artifact_ref,
                      semantic_version = EXCLUDED.semantic_version,
                      lineage_classification = EXCLUDED.lineage_classification
                  WHERE managed_program_registry.status <> 'revoked'
                RETURNING program_digest
            """),
                {
                    "tenant_id": tenant_id,
                    "program_id": promotion["program_id"],
                    "digest": promotion["candidate_digest"],
                    "signature": artifact_signature,
                    "model_config_digest": promotion["model_config_digest"],
                    "dependency_digest": promotion["dependency_digest"],
                    "actor": actor,
                    "optimization_id": promotion["optimization_id"],
                    "evaluation_id": promotion["evaluation_id"],
                    "artifact_ref": promotion["candidate_artifact_ref"],
                    "semantic_version": f"promotion-{promotion_id}",
                    "lineage": promotion["lineage_classification"],
                },
            ).one_or_none()
            if registered is None:
                raise ManagedSecurityError("revoked program cannot be activated")
            binding = (
                session.execute(
                    text("""
                INSERT INTO managed_dspy_deployment_bindings
                  (tenant_id, deployment_id, program_id, active_program_digest,
                   previous_program_digest, promotion_id, rollout_generation, activated_by)
                VALUES (:tenant_id, :deployment_id, :program_id, :active_digest,
                        :previous_digest, CAST(:promotion_id AS uuid), 1, :actor)
                ON CONFLICT (tenant_id, deployment_id, program_id) DO UPDATE
                  SET previous_program_digest = managed_dspy_deployment_bindings.active_program_digest,
                      active_program_digest = EXCLUDED.active_program_digest,
                      promotion_id = EXCLUDED.promotion_id,
                      last_rollback_id = NULL,
                      rollout_generation = managed_dspy_deployment_bindings.rollout_generation + 1,
                      activated_by = EXCLUDED.activated_by, activated_at = now()
                RETURNING *
            """),
                    {
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": promotion["program_id"],
                        "active_digest": promotion["candidate_digest"],
                        "previous_digest": (
                            None if previous is None else previous.program_digest
                        ),
                        "promotion_id": promotion_id,
                        "actor": actor,
                    },
                )
                .mappings()
                .one()
            )
            session.execute(
                text("""
                UPDATE managed_dspy_promotions SET status = 'activated'
                 WHERE promotion_id = CAST(:promotion_id AS uuid)
            """),
                {"promotion_id": promotion_id},
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.program.activated",
                aggregate_id=promotion_id,
                payload={
                    "program_id": promotion["program_id"],
                    "program_digest": promotion["candidate_digest"],
                    "rollout_generation": binding["rollout_generation"],
                },
            )
            return dict(binding)

    def stage(
        self,
        *,
        promotion_id: str,
        tenant_id: str,
        deployment_id: str,
        actor: str,
        sign: Callable[[Mapping[str, Any]], str],
    ) -> dict[str, Any]:
        """Register an approved candidate without changing a deployment binding."""

        with unit_of_work() as session:
            promotion = (
                session.execute(
                    text("""
                SELECT p.*, o.candidate_artifact_ref, o.lineage_classification,
                       o.model_config_digest, o.dependency_digest
                  FROM managed_dspy_promotions p
                  JOIN managed_dspy_optimizations o ON o.optimization_id = p.optimization_id
                 WHERE p.promotion_id = CAST(:promotion_id AS uuid)
                   AND p.tenant_id = :tenant_id AND p.deployment_id = :deployment_id
                   AND p.status = 'approved' AND p.target_stage = 'staged'
                   AND o.status = 'candidate'
                 FOR UPDATE OF p, o
            """),
                    {
                        "promotion_id": promotion_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if promotion is None:
                raise ManagedSecurityError("approved staging promotion is unavailable")
            registry_record = {
                "tenant_id": tenant_id,
                "program_id": str(promotion["program_id"]),
                "program_digest": str(promotion["candidate_digest"]),
                "model_config_digest": str(promotion["model_config_digest"]),
                "dependency_digest": str(promotion["dependency_digest"]),
                "status": "approved",
            }
            artifact_signature = sign(program_registry_payload(registry_record))
            registered = (
                session.execute(
                    text("""
                INSERT INTO managed_program_registry
                  (tenant_id, program_id, program_digest, artifact_signature,
                   model_config_digest, dependency_digest, status, approved_by,
                   approved_at, source_optimization_id, source_evaluation_id,
                   artifact_ref, semantic_version, lineage_classification)
                VALUES (:tenant_id, :program_id, :digest, :signature,
                        :model_config_digest, :dependency_digest, 'approved', :actor,
                        now(), :optimization_id, :evaluation_id, :artifact_ref,
                        :semantic_version, :lineage)
                ON CONFLICT (tenant_id, program_id, program_digest) DO UPDATE
                  SET artifact_signature = EXCLUDED.artifact_signature,
                      model_config_digest = EXCLUDED.model_config_digest,
                      dependency_digest = EXCLUDED.dependency_digest,
                      approved_by = EXCLUDED.approved_by,
                      approved_at = now(),
                      source_optimization_id = EXCLUDED.source_optimization_id,
                      source_evaluation_id = EXCLUDED.source_evaluation_id,
                      artifact_ref = EXCLUDED.artifact_ref,
                      semantic_version = EXCLUDED.semantic_version,
                      lineage_classification = EXCLUDED.lineage_classification
                  WHERE managed_program_registry.status <> 'revoked'
                RETURNING *
            """),
                    {
                        "tenant_id": tenant_id,
                        "program_id": promotion["program_id"],
                        "digest": promotion["candidate_digest"],
                        "signature": artifact_signature,
                        "model_config_digest": promotion["model_config_digest"],
                        "dependency_digest": promotion["dependency_digest"],
                        "actor": actor,
                        "optimization_id": promotion["optimization_id"],
                        "evaluation_id": promotion["evaluation_id"],
                        "artifact_ref": promotion["candidate_artifact_ref"],
                        "semantic_version": f"promotion-{promotion_id}",
                        "lineage": promotion["lineage_classification"],
                    },
                )
                .mappings()
                .one_or_none()
            )
            if registered is None:
                raise ManagedSecurityError("revoked program cannot be staged")
            session.execute(
                text("""
                UPDATE managed_dspy_promotions SET status = 'staged'
                 WHERE promotion_id = CAST(:promotion_id AS uuid)
            """),
                {"promotion_id": promotion_id},
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.program.staged",
                aggregate_id=promotion_id,
                payload={
                    "program_id": promotion["program_id"],
                    "program_digest": promotion["candidate_digest"],
                },
            )
            return dict(registered)

    def request_rollback(
        self,
        *,
        rollback_id: str,
        tenant_id: str,
        deployment_id: str,
        program_id: str,
        target_program_digest: str,
        policy_version: str,
        request_digest: str,
        actor: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            binding = (
                session.execute(
                    text("""
                    SELECT active_program_digest, previous_program_digest
                      FROM managed_dspy_deployment_bindings
                     WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                       AND program_id = :program_id
                     FOR SHARE
                """),
                    {
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": program_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if (
                binding is None
                or binding["previous_program_digest"] != target_program_digest
            ):
                raise ManagedSecurityError(
                    "rollback target is not the deployment's previous program"
                )
            target = session.execute(
                text("""
                    SELECT 1 FROM managed_program_registry
                     WHERE tenant_id = :tenant_id AND program_id = :program_id
                       AND program_digest = :target_digest AND status = 'approved'
                """),
                {
                    "tenant_id": tenant_id,
                    "program_id": program_id,
                    "target_digest": target_program_digest,
                },
            ).one_or_none()
            if target is None:
                raise ManagedSecurityError("rollback target is unavailable or revoked")
            row = (
                session.execute(
                    text("""
                    INSERT INTO managed_dspy_rollbacks
                      (rollback_id, tenant_id, deployment_id, program_id,
                       from_program_digest, target_program_digest, policy_version,
                       request_digest, requested_by)
                    VALUES (CAST(:rollback_id AS uuid), :tenant_id, :deployment_id,
                            :program_id, :from_digest, :target_digest, :policy_version,
                            :request_digest, :actor)
                    RETURNING *
                """),
                    {
                        "rollback_id": rollback_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": program_id,
                        "from_digest": binding["active_program_digest"],
                        "target_digest": target_program_digest,
                        "policy_version": policy_version,
                        "request_digest": request_digest,
                        "actor": actor,
                    },
                )
                .mappings()
                .one()
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.rollback.requested",
                aggregate_id=rollback_id,
                payload={
                    "program_id": program_id,
                    "from_program_digest": binding["active_program_digest"],
                    "target_program_digest": target_program_digest,
                },
            )
            return dict(row)

    def approve_rollback(
        self,
        *,
        rollback_id: str,
        tenant_id: str,
        approver: str,
        request_digest: str,
        approval_signature: str,
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            row = (
                session.execute(
                    text("""
                    UPDATE managed_dspy_rollbacks
                       SET status = 'approved', approved_by = :approver,
                           approval_signature = :signature, resolved_at = now()
                     WHERE rollback_id = CAST(:rollback_id AS uuid)
                       AND tenant_id = :tenant_id AND status = 'pending'
                       AND requested_by <> :approver AND request_digest = :request_digest
                    RETURNING *
                """),
                    {
                        "rollback_id": rollback_id,
                        "tenant_id": tenant_id,
                        "approver": approver,
                        "signature": approval_signature,
                        "request_digest": request_digest,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ManagedSecurityError(
                    "rollback approval is stale, altered, foreign or self-approved"
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=str(row["deployment_id"]),
                actor=approver,
                event_type="dspy.rollback.approved",
                aggregate_id=rollback_id,
                payload={
                    "request_digest": request_digest,
                    "target_program_digest": row["target_program_digest"],
                },
            )
            return dict(row)

    def apply_rollback(
        self,
        *,
        rollback_id: str,
        tenant_id: str,
        deployment_id: str,
        actor: str,
        sign: Callable[[Mapping[str, Any]], str],
    ) -> dict[str, Any]:
        with unit_of_work() as session:
            rollback = (
                session.execute(
                    text("""
                    SELECT r.*, p.model_config_digest, p.dependency_digest
                      FROM managed_dspy_rollbacks r
                      JOIN managed_program_registry p
                        ON p.tenant_id = r.tenant_id AND p.program_id = r.program_id
                       AND p.program_digest = r.target_program_digest
                     WHERE r.rollback_id = CAST(:rollback_id AS uuid)
                       AND r.tenant_id = :tenant_id AND r.deployment_id = :deployment_id
                       AND r.status = 'approved' AND p.status = 'approved'
                     FOR UPDATE OF r, p
                """),
                    {
                        "rollback_id": rollback_id,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if rollback is None:
                raise ManagedSecurityError(
                    "approved rollback target is unavailable or revoked"
                )
            binding = (
                session.execute(
                    text("""
                    SELECT * FROM managed_dspy_deployment_bindings
                     WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                       AND program_id = :program_id
                       AND active_program_digest = :from_digest
                       AND previous_program_digest = :target_digest
                     FOR UPDATE
                """),
                    {
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": rollback["program_id"],
                        "from_digest": rollback["from_program_digest"],
                        "target_digest": rollback["target_program_digest"],
                    },
                )
                .mappings()
                .one_or_none()
            )
            if binding is None:
                raise ManagedSecurityError(
                    "rollback request is stale for the deployment generation"
                )
            registry_record = {
                "tenant_id": tenant_id,
                "program_id": str(rollback["program_id"]),
                "program_digest": str(rollback["target_program_digest"]),
                "model_config_digest": str(rollback["model_config_digest"]),
                "dependency_digest": str(rollback["dependency_digest"]),
                "status": "active",
            }
            signature = sign(program_registry_payload(registry_record))
            session.execute(
                text("""
                    UPDATE managed_program_registry
                       SET status = 'approved', activated_at = NULL
                     WHERE tenant_id = :tenant_id AND program_id = :program_id
                       AND program_digest = :from_digest AND status = 'active'
                """),
                {
                    "tenant_id": tenant_id,
                    "program_id": rollback["program_id"],
                    "from_digest": rollback["from_program_digest"],
                },
            )
            activated = session.execute(
                text("""
                    UPDATE managed_program_registry
                       SET status = 'active', artifact_signature = :signature,
                           activated_at = now(), revoked_at = NULL
                     WHERE tenant_id = :tenant_id AND program_id = :program_id
                       AND program_digest = :target_digest AND status = 'approved'
                    RETURNING program_digest
                """),
                {
                    "tenant_id": tenant_id,
                    "program_id": rollback["program_id"],
                    "target_digest": rollback["target_program_digest"],
                    "signature": signature,
                },
            ).one_or_none()
            if activated is None:
                raise ManagedSecurityError("rollback target became unavailable")
            updated = (
                session.execute(
                    text("""
                    UPDATE managed_dspy_deployment_bindings
                       SET active_program_digest = :target_digest,
                           previous_program_digest = :from_digest,
                           last_rollback_id = CAST(:rollback_id AS uuid),
                           rollout_generation = rollout_generation + 1,
                           activated_by = :actor, activated_at = now()
                     WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                       AND program_id = :program_id
                    RETURNING *
                """),
                    {
                        "target_digest": rollback["target_program_digest"],
                        "from_digest": rollback["from_program_digest"],
                        "rollback_id": rollback_id,
                        "actor": actor,
                        "tenant_id": tenant_id,
                        "deployment_id": deployment_id,
                        "program_id": rollback["program_id"],
                    },
                )
                .mappings()
                .one()
            )
            session.execute(
                text("""
                    UPDATE managed_dspy_rollbacks SET status = 'applied', applied_at = now()
                     WHERE rollback_id = CAST(:rollback_id AS uuid)
                """),
                {"rollback_id": rollback_id},
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor=actor,
                event_type="dspy.rollback.applied",
                aggregate_id=rollback_id,
                payload={
                    "program_id": rollback["program_id"],
                    "program_digest": rollback["target_program_digest"],
                    "rollout_generation": updated["rollout_generation"],
                },
            )
            return dict(updated)

    def history(
        self, *, tenant_id: str, deployment_id: str
    ) -> dict[str, list[dict[str, Any]]]:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            values = {"tenant_id": tenant_id, "deployment_id": deployment_id}
            evaluations = (
                session.execute(
                    text("""
                SELECT * FROM managed_dspy_evaluations
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                 ORDER BY created_at DESC LIMIT 100
            """),
                    values,
                )
                .mappings()
                .all()
            )
            optimizations = (
                session.execute(
                    text("""
                SELECT * FROM managed_dspy_optimizations
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                 ORDER BY created_at DESC LIMIT 100
            """),
                    values,
                )
                .mappings()
                .all()
            )
            promotions = (
                session.execute(
                    text("""
                SELECT * FROM managed_dspy_promotions
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                 ORDER BY requested_at DESC LIMIT 100
            """),
                    values,
                )
                .mappings()
                .all()
            )
            rollbacks = (
                session.execute(
                    text("""
                SELECT * FROM managed_dspy_rollbacks
                 WHERE tenant_id = :tenant_id AND deployment_id = :deployment_id
                 ORDER BY requested_at DESC LIMIT 100
            """),
                    values,
                )
                .mappings()
                .all()
            )
        return {
            "evaluations": [dict(row) for row in evaluations],
            "optimizations": [dict(row) for row in optimizations],
            "promotions": [dict(row) for row in promotions],
            "rollbacks": [dict(row) for row in rollbacks],
        }
