"""Managed agent-run admission surface.

The v1 run API accepts file references and a caller-supplied tenant label for
upstream compatibility. Managed deployments use this v2 surface instead: the
server resolves membership, admits only the approved triage workflow, and puts
the signed admission envelope on the queue.
"""

from __future__ import annotations

import hashlib
import base64
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.agents.managed_execution import ManagedAuthority, ManagedSecurityError, TenantContext
from core.agents.queue import enqueue_run, build_start_job
from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.routing import Auth, RouterMeta
from core.storage.models import User


router = APIRouter()


def _managed_enabled() -> bool:
    return os.getenv("VIGIL_EXECUTION_PROFILE", "standalone").lower() == "managed"


ROUTER_META = RouterMeta(
    prefix="/api/v2/agent-runs",
    tags=["managed-agent-runs"],
    auth=Auth.REQUIRED,
    enabled=_managed_enabled,
)


class ManagedStartRequest(BaseModel):
    workflow_id: str = Field(default="triage-v1", pattern=r"^triage-v1$")
    finding_ids: list[str] = Field(default_factory=list, min_length=1, max_length=100)
    prompt: str = Field(default="", max_length=4000)


class ManagedStartResponse(BaseModel):
    run_id: str
    job_id: str
    execution_id: str
    tenant_id: str
    deployment_id: str


class ManagedRunResponse(BaseModel):
    run_id: str
    execution_id: str
    tenant_id: str
    deployment_id: str
    status: str
    workflow_id: str


class ManagedRunListResponse(BaseModel):
    runs: list[ManagedRunResponse]
    count: int


class ManagedApprovalRequest(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=500)
    argument_digest: str = Field(min_length=1, max_length=128)


@dataclass(frozen=True)
class MembershipBinding:
    tenant_id: str
    deployment_id: str
    roles: tuple[str, ...]
    membership_version: int = 1
    policy_version: str = "managed-v1"
    issuer: str = "local"


class MembershipResolver:
    """Resolve membership from deployment-owned configuration.

    ``VIGIL_MANAGED_MEMBERSHIPS`` is an operator-provisioned mapping, not a
    request-controlled value. A database-backed resolver can replace this
    adapter without changing the v2 route or signed contract.
    """

    def resolve(self, user: User, tenant_hint: Optional[str]) -> MembershipBinding:
        raw = os.getenv("VIGIL_MANAGED_MEMBERSHIPS", "")
        if not raw:
            raise HTTPException(status_code=503, detail="managed membership authority is unavailable")
        try:
            mapping = json.loads(raw)
            candidates = mapping[str(user.user_id)]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=503, detail="managed membership authority is unavailable") from exc
        if not isinstance(candidates, list):
            raise HTTPException(status_code=503, detail="managed membership authority is unavailable")
        matches = [item for item in candidates if isinstance(item, dict)]
        if tenant_hint:
            matches = [item for item in matches if item.get("tenant_id") == tenant_hint]
        if len(matches) != 1:
            raise HTTPException(status_code=403, detail="tenant membership is not uniquely authorized")
        item = matches[0]
        try:
            return MembershipBinding(
                tenant_id=str(item["tenant_id"]),
                deployment_id=str(item["deployment_id"]),
                roles=tuple(str(role) for role in item.get("roles", [])),
                membership_version=int(item.get("membership_version", 1)),
                policy_version=str(item.get("policy_version", "managed-v1")),
                issuer=str(item.get("issuer", "local")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="invalid managed membership binding") from exc


_resolver = MembershipResolver()


def _authority_from_trust_material() -> ManagedAuthority:
    raw = os.getenv("VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY", "")
    if not raw:
        return ManagedAuthority()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        padded = raw + "=" * (-len(raw) % 4)
        private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
        from core.agents.managed_execution import Ed25519Signer

        return ManagedAuthority(signer=Ed25519Signer(private))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("managed authority private key is invalid") from exc


def validate_managed_startup() -> None:
    """Fail startup before serving requests when managed trust is incomplete."""
    if not _managed_enabled():
        return
    required = (
        "VIGIL_DEPLOYMENT_ID",
        "VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY",
        "VIGIL_MANAGED_MEMBERSHIPS",
    )
    missing = [name for name in required if not os.getenv(name)]
    if missing or os.getenv("DEV_MODE", "false").lower() == "true":
        raise RuntimeError("managed execution trust configuration is incomplete")


_authority = _authority_from_trust_material()
_runs: Dict[str, ManagedRunResponse] = {}
_run_subjects: Dict[str, str] = {}
_TRIAGE_PROGRAM_DIGEST = hashlib.sha256(b"vigil-dspy-triage-v1").hexdigest()
_TRIAGE_WORKFLOW_DIGEST = hashlib.sha256(b"vigil-managed-triage-v1").hexdigest()


def _require_managed_profile() -> None:
    if not _managed_enabled():
        raise HTTPException(status_code=404, detail="managed execution profile is disabled")
    if os.getenv("DEV_MODE", "false").lower() == "true":
        raise HTTPException(status_code=503, detail="managed execution refuses development authentication bypass")


def _run_for_tenant(run_id: str, user: User) -> ManagedRunResponse:
    try:
        existing = _runs[str(uuid.UUID(run_id))]
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=404, detail="managed run not found") from exc
    binding = _resolver.resolve(user, None)
    if binding.tenant_id != existing.tenant_id:
        raise HTTPException(status_code=403, detail="run ownership is not currently authorized")
    return existing


def _owned_run(run_id: str, user: User) -> ManagedRunResponse:
    existing = _run_for_tenant(run_id, user)
    if _run_subjects.get(existing.run_id) != str(user.user_id):
        raise HTTPException(status_code=403, detail="run ownership is not currently authorized")
    return existing


@router.post("", response_model=ManagedStartResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[permission_gate("ai_chat.use")])
async def start_managed_run(
    body: ManagedStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-ID"),
) -> ManagedStartResponse:
    _require_managed_profile()
    binding = _resolver.resolve(current_user, x_tenant_id)
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    context = TenantContext(
        tenant_id=binding.tenant_id,
        deployment_id=binding.deployment_id,
        subject_id=str(current_user.user_id),
        issuer=binding.issuer,
        roles=binding.roles,
        membership_version=binding.membership_version,
        policy_version=binding.policy_version,
        request_id=request_id,
    )
    request_data = {"workflow_id": body.workflow_id, "finding_ids": body.finding_ids, "prompt": body.prompt}
    try:
        envelope = _authority.admit(
            context,
            admission_id=str(uuid.uuid4()),
            workflow_id=body.workflow_id,
            workflow_digest=_TRIAGE_WORKFLOW_DIGEST,
            program_id="triage-dspy-v1",
            program_digest=_TRIAGE_PROGRAM_DIGEST,
            request=request_data,
        )
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed admission denied") from exc

    run_id = str(uuid.uuid4())
    job = build_start_job(
        run_id=run_id,
        run_kind="investigate",
        request={
            "arch": "",
            "playbook": "workflow:triage-v1",
            "config": "",
            "prompt": body.prompt,
            "finding_ids": body.finding_ids,
        },
        enqueued_by=str(current_user.user_id),
        managed_envelope=envelope.as_dict(),
    )
    try:
        job_id = await enqueue_run(job)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="managed run queue unavailable") from exc
    result = ManagedRunResponse(
        run_id=run_id,
        execution_id=envelope.execution_id,
        tenant_id=binding.tenant_id,
        deployment_id=binding.deployment_id,
        status="queued",
        workflow_id=body.workflow_id,
    )
    _runs[run_id] = result
    _run_subjects[run_id] = str(current_user.user_id)
    return ManagedStartResponse(
        run_id=run_id,
        job_id=job_id,
        execution_id=envelope.execution_id,
        tenant_id=binding.tenant_id,
        deployment_id=binding.deployment_id,
    )


@router.get("", response_model=ManagedRunListResponse)
def list_managed_runs(current_user: User = Depends(get_current_user)) -> ManagedRunListResponse:
    _require_managed_profile()
    _resolver.resolve(current_user, None)
    owned = [run for run in _runs.values() if _run_subjects.get(run.run_id) == str(current_user.user_id)]
    return ManagedRunListResponse(runs=sorted(owned, key=lambda item: item.run_id), count=len(owned))


@router.get("/{run_id}", response_model=ManagedRunResponse)
def get_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    return _owned_run(run_id, current_user)


@router.post("/{run_id}/cancel", response_model=ManagedRunResponse)
def cancel_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    existing = _owned_run(run_id, current_user)
    _authority.revoke(existing.tenant_id)
    cancelled = existing.model_copy(update={"status": "cancelled"})
    _runs[existing.run_id] = cancelled
    return cancelled


@router.post("/{run_id}/approve", response_model=ManagedRunResponse)
def approve_managed_run(
    run_id: str,
    body: ManagedApprovalRequest,
    current_user: User = Depends(get_current_user),
) -> ManagedRunResponse:
    _require_managed_profile()
    existing = _run_for_tenant(run_id, current_user)
    approver_binding = _resolver.resolve(current_user, None)
    if not {"approver", "admin"}.intersection(approver_binding.roles):
        raise HTTPException(status_code=403, detail="authenticated subject is not an approver")
    if _run_subjects.get(existing.run_id) == str(current_user.user_id):
        raise HTTPException(status_code=403, detail="approval requires a distinct authorized approver")
    if not body.action or not body.resource or not body.argument_digest:
        raise HTTPException(status_code=422, detail="approval binding is incomplete")
    approved = existing.model_copy(update={"status": "approved"})
    _runs[existing.run_id] = approved
    return approved


@router.post("/{run_id}/resume", response_model=ManagedRunResponse, status_code=status.HTTP_202_ACCEPTED)
def resume_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    existing = _owned_run(run_id, current_user)
    resumed = existing.model_copy(update={"status": "queued"})
    _runs[existing.run_id] = resumed
    return resumed
