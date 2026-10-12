"""Authenticated tenant-local DSPy lifecycle orchestration surface."""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any, Literal, Mapping

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from core.agents.dspy_lifecycle_store import DSPyLifecycleStore
from core.agents.managed_execution import ManagedSecurityError, managed_digest
from core.agents.managed_service import authority
from core.api.v2.agent_runs_router import MembershipBinding, _resolver
from core.auth.current_user import get_current_user
from core.routing import Auth, RouterMeta
from core.storage.models import User
from services.reasoner.lifecycle import EvaluationThresholds, metric_contract_digest


def _managed_enabled() -> bool:
    return os.getenv("VIGIL_EXECUTION_PROFILE", "standalone").lower() == "managed"


router = APIRouter()
ROUTER_META = RouterMeta(
    prefix="/api/v2/dspy",
    tags=["managed-dspy-lifecycle"],
    auth=Auth.REQUIRED,
    enabled=_managed_enabled,
)
_store = DSPyLifecycleStore()


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetRegistration(ClosedModel):
    dataset_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    version: int = Field(gt=0)
    object_ref: str = Field(pattern=r"^local:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
    content_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    schema_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    split_manifest: dict[Literal["train", "development", "holdout", "safety"], int]
    use_purpose: str = Field(min_length=1, max_length=500)
    sensitivity: Literal["synthetic", "internal", "confidential", "restricted"]
    retention_policy_ref: str = Field(
        pattern=r"^local:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$"
    )
    access_policy_ref: str = Field(pattern=r"^local:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class Thresholds(ClosedModel):
    minimum_pass_rate: float = Field(ge=0, le=1)
    minimum_grounding_rate: float = Field(ge=0, le=1)
    minimum_action_safety_rate: float = Field(ge=0, le=1)
    maximum_failure_rate: float = Field(ge=0, le=1)


class EvaluationRequest(ClosedModel):
    dataset_id: uuid.UUID
    program_id: str = Field(min_length=1, max_length=128)
    program_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    model_config_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    evaluator_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    split_name: Literal["development", "holdout", "safety"]
    seed: int = 9
    thresholds: Thresholds
    execution_location: Literal["tenant-local", "byoc-local"]
    max_tokens: int = Field(gt=0)
    max_cost_microusd: int = Field(gt=0)


class OptimizationRequest(ClosedModel):
    dataset_id: uuid.UUID
    base_program_id: str = Field(min_length=1, max_length=128)
    base_program_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    optimizer_name: Literal["bootstrap-few-shot", "miprov2"]
    optimizer_config: dict[str, Any]
    model_config_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    dependency_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    seed: int = 9
    max_tokens: int = Field(gt=0)
    max_cost_microusd: int = Field(gt=0)
    lineage_classification: Literal["synthetic", "tenant-derived", "redistributable"]


class PromotionRequest(ClosedModel):
    optimization_id: uuid.UUID
    holdout_evaluation_id: uuid.UUID
    target_stage: Literal["staged", "active"]


class PromotionApproval(ClosedModel):
    request_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class RollbackRequest(ClosedModel):
    program_id: str = Field(min_length=1, max_length=128)
    target_program_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


def _binding(user: User, roles: set[str]) -> MembershipBinding:
    binding = _resolver.resolve(user, None)
    if not roles.intersection(binding.roles):
        raise HTTPException(
            status_code=403,
            detail="tenant role does not authorize this DSPy lifecycle operation",
        )
    return binding


def _serialize(value: Any) -> Any:
    if isinstance(value, (uuid.UUID, datetime)):
        return str(value)
    if isinstance(value, Mapping):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


def _call(operation):
    try:
        return _serialize(operation())
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="tenant-local DSPy lifecycle state is unavailable"
        ) from exc


@router.post("/datasets", status_code=status.HTTP_201_CREATED)
def register_dataset(
    body: DatasetRegistration, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "analyst"})
    if set(body.split_manifest) != {"train", "development", "holdout", "safety"} or any(
        value <= 0 for value in body.split_manifest.values()
    ):
        raise HTTPException(
            status_code=422, detail="all four dataset splits must be non-empty"
        )
    return _call(
        lambda: _store.register_dataset(
            dataset_id=str(body.dataset_id),
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            name=body.name,
            version=body.version,
            object_ref=body.object_ref,
            content_digest=body.content_digest,
            schema_digest=body.schema_digest,
            split_manifest={
                str(key): value for key, value in body.split_manifest.items()
            },
            use_purpose=body.use_purpose,
            sensitivity=body.sensitivity,
            retention_policy_ref=body.retention_policy_ref,
            access_policy_ref=body.access_policy_ref,
            actor=str(user.user_id),
        )
    )


@router.post("/evaluations", status_code=status.HTTP_202_ACCEPTED)
def create_evaluation(
    body: EvaluationRequest, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "analyst"})
    thresholds = EvaluationThresholds(**body.thresholds.model_dump())
    evaluation_id = str(uuid.uuid4())
    return _call(
        lambda: _store.create_evaluation(
            evaluation_id=evaluation_id,
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            dataset_id=str(body.dataset_id),
            program_id=body.program_id,
            program_digest=body.program_digest,
            model_config_digest=body.model_config_digest,
            evaluator_digest=body.evaluator_digest,
            metric_contract_digest=metric_contract_digest(),
            split_name=body.split_name,
            seed=body.seed,
            thresholds=thresholds.__dict__,
            execution_location=body.execution_location,
            max_tokens=body.max_tokens,
            max_cost_microusd=body.max_cost_microusd,
            actor=str(user.user_id),
        )
    )


@router.post("/optimizations", status_code=status.HTTP_202_ACCEPTED)
def create_optimization(
    body: OptimizationRequest, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "analyst"})
    optimization_id = str(uuid.uuid4())
    return _call(
        lambda: _store.create_optimization(
            optimization_id=optimization_id,
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            dataset_id=str(body.dataset_id),
            base_program_id=body.base_program_id,
            base_program_digest=body.base_program_digest,
            optimizer_name=body.optimizer_name,
            optimizer_config=body.optimizer_config,
            optimizer_config_digest=managed_digest(body.optimizer_config),
            model_config_digest=body.model_config_digest,
            dependency_digest=body.dependency_digest,
            seed=body.seed,
            max_tokens=body.max_tokens,
            max_cost_microusd=body.max_cost_microusd,
            lineage_classification=body.lineage_classification,
            actor=str(user.user_id),
        )
    )


@router.post("/promotions", status_code=status.HTTP_202_ACCEPTED)
def request_promotion(
    body: PromotionRequest, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "analyst"})
    promotion_id = str(uuid.uuid4())
    request_digest = managed_digest(
        {
            "promotion_id": promotion_id,
            "tenant_id": binding.tenant_id,
            "deployment_id": binding.deployment_id,
            "optimization_id": str(body.optimization_id),
            "evaluation_id": str(body.holdout_evaluation_id),
            "target_stage": body.target_stage,
            "policy_version": binding.policy_version,
        }
    )
    return _call(
        lambda: _store.request_promotion(
            promotion_id=promotion_id,
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            optimization_id=str(body.optimization_id),
            evaluation_id=str(body.holdout_evaluation_id),
            target_stage=body.target_stage,
            policy_version=binding.policy_version,
            request_digest=request_digest,
            actor=str(user.user_id),
        )
    )


@router.post("/promotions/{promotion_id}/approve")
def approve_promotion(
    promotion_id: uuid.UUID,
    body: PromotionApproval,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "approver"})
    signature = authority.signer.sign(
        {
            "purpose": "dspy-promotion-approval",
            "tenant_id": binding.tenant_id,
            "promotion_id": str(promotion_id),
            "request_digest": body.request_digest,
            "approver": str(user.user_id),
        }
    )
    return _call(
        lambda: _store.approve_promotion(
            promotion_id=str(promotion_id),
            tenant_id=binding.tenant_id,
            approver=str(user.user_id),
            request_digest=body.request_digest,
            approval_signature=signature,
        )
    )


@router.post("/promotions/{promotion_id}/activate")
def activate_promotion(
    promotion_id: uuid.UUID, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin"})
    return _call(
        lambda: _store.activate(
            promotion_id=str(promotion_id),
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            actor=str(user.user_id),
            sign=authority.signer.sign,
        )
    )


@router.post("/promotions/{promotion_id}/stage")
def stage_promotion(
    promotion_id: uuid.UUID, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin"})
    return _call(
        lambda: _store.stage(
            promotion_id=str(promotion_id),
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            actor=str(user.user_id),
            sign=authority.signer.sign,
        )
    )


@router.post("/rollbacks", status_code=status.HTTP_202_ACCEPTED)
def request_rollback(
    body: RollbackRequest, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin"})
    rollback_id = str(uuid.uuid4())
    request_digest = managed_digest(
        {
            "rollback_id": rollback_id,
            "tenant_id": binding.tenant_id,
            "deployment_id": binding.deployment_id,
            "program_id": body.program_id,
            "target_program_digest": body.target_program_digest,
            "policy_version": binding.policy_version,
        }
    )
    return _call(
        lambda: _store.request_rollback(
            rollback_id=rollback_id,
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            program_id=body.program_id,
            target_program_digest=body.target_program_digest,
            policy_version=binding.policy_version,
            request_digest=request_digest,
            actor=str(user.user_id),
        )
    )


@router.post("/rollbacks/{rollback_id}/approve")
def approve_rollback(
    rollback_id: uuid.UUID,
    body: PromotionApproval,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "approver"})
    signature = authority.signer.sign(
        {
            "purpose": "dspy-rollback-approval",
            "tenant_id": binding.tenant_id,
            "rollback_id": str(rollback_id),
            "request_digest": body.request_digest,
            "approver": str(user.user_id),
        }
    )
    return _call(
        lambda: _store.approve_rollback(
            rollback_id=str(rollback_id),
            tenant_id=binding.tenant_id,
            approver=str(user.user_id),
            request_digest=body.request_digest,
            approval_signature=signature,
        )
    )


@router.post("/rollbacks/{rollback_id}/apply")
def apply_rollback(
    rollback_id: uuid.UUID, user: User = Depends(get_current_user)
) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin"})
    return _call(
        lambda: _store.apply_rollback(
            rollback_id=str(rollback_id),
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
            actor=str(user.user_id),
            sign=authority.signer.sign,
        )
    )


@router.get("/history")
def lifecycle_history(user: User = Depends(get_current_user)) -> dict[str, Any]:
    binding = _binding(user, {"admin", "tenant_admin", "analyst", "approver", "viewer"})
    return _call(
        lambda: _store.history(
            tenant_id=binding.tenant_id,
            deployment_id=binding.deployment_id,
        )
    )
