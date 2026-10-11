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

from core.agents.managed_execution import ManagedAuthority, ManagedSecurityError, QueueEnvelope, TenantContext
from core.agents.managed_service import authority as shared_authority
from core.agents.managed_store import ManagedRunStore
from core.agents.queue import enqueue_run, build_resume_job, build_start_job
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
        "VIGIL_MANAGED_DATABASE_URL",
        "VIGIL_MANAGED_MTLS_CA",
    )
    missing = [name for name in required if not os.getenv(name)]
    if (
        missing
        or os.getenv("DEV_MODE", "false").lower() == "true"
        or os.getenv("VIGIL_MANAGED_FAIL_OPEN_REVOCATION", "false").lower() == "true"
    ):
        raise RuntimeError("managed execution trust configuration is incomplete")


_authority = shared_authority
_store = ManagedRunStore()
try:
    from services.reasoner.programs.triage_v1 import artifact_digest as _triage_artifact_digest

    _TRIAGE_PROGRAM_DIGEST = _triage_artifact_digest()
except (ImportError, OSError):
    _TRIAGE_PROGRAM_DIGEST = ""
_TRIAGE_WORKFLOW_DIGEST = hashlib.sha256(b"vigil-managed-triage-v1").hexdigest()


def _require_managed_profile() -> None:
    if not _managed_enabled():
        raise HTTPException(status_code=404, detail="managed execution profile is disabled")
    if os.getenv("DEV_MODE", "false").lower() == "true":
        raise HTTPException(status_code=503, detail="managed execution refuses development authentication bypass")


def _run_for_tenant(run_id: str, user: User) -> ManagedRunResponse:
    try:
        normalized = str(uuid.UUID(run_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="managed run not found") from exc
    binding = _resolver.resolve(user, None)
    row = _store.get(normalized, binding.tenant_id, str(user.user_id))
    if row is None:
        raise HTTPException(status_code=404, detail="managed run not found")
    return ManagedRunResponse(**{key: str(row[key]) for key in ("run_id", "execution_id", "tenant_id", "deployment_id", "status", "workflow_id")})


def _owned_run(run_id: str, user: User) -> ManagedRunResponse:
    return _run_for_tenant(run_id, user)


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
    run_id = str(uuid.uuid4())
    job_request = {
        "arch": "",
        "playbook": "workflow:triage-v1",
        "config": "",
        "prompt": body.prompt,
        "finding_ids": body.finding_ids,
    }
    try:
        envelope = _authority.admit(
            context,
            admission_id=str(uuid.uuid4()),
            workflow_id=body.workflow_id,
            workflow_digest=_TRIAGE_WORKFLOW_DIGEST,
            program_id="triage-dspy-v1",
            program_digest=_TRIAGE_PROGRAM_DIGEST,
            request=job_request,
            references={
                "run_id": run_id,
                "run_kind": "investigate",
                "workflow_id": body.workflow_id,
                "workflow_digest": _TRIAGE_WORKFLOW_DIGEST,
                "program_id": "triage-dspy-v1",
                "program_digest": _TRIAGE_PROGRAM_DIGEST,
            },
        )
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed admission denied") from exc

    job = build_start_job(
        run_id=run_id,
        run_kind="investigate",
        request=job_request,
        enqueued_by=str(current_user.user_id),
        managed_envelope=envelope.as_dict(),
    )
    try:
        _store.create(
            run_id=run_id,
            subject_id=str(current_user.user_id),
            run_kind="investigate",
            workflow_id=body.workflow_id,
            status="queued",
            request=job_request,
            envelope=envelope.as_dict(),
            admission=envelope.admission,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="managed admission store unavailable") from exc
    try:
        job_id = await enqueue_run(job)
    except Exception as exc:
        # The committed outbox is intentionally retained for a publisher retry.
        raise HTTPException(status_code=503, detail="managed run queue unavailable") from exc
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
    binding = _resolver.resolve(current_user, None)
    rows = _store.list(binding.tenant_id, str(current_user.user_id))
    owned = [ManagedRunResponse(**{key: str(row[key]) for key in ("run_id", "execution_id", "tenant_id", "deployment_id", "status", "workflow_id")}) for row in rows]
    return ManagedRunListResponse(runs=owned, count=len(owned))


@router.get("/{run_id}", response_model=ManagedRunResponse)
def get_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    return _owned_run(run_id, current_user)


@router.post("/{run_id}/cancel", response_model=ManagedRunResponse)
def cancel_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    existing = _owned_run(run_id, current_user)
    _authority.cancel_execution(existing.execution_id)
    binding = _resolver.resolve(current_user, None)
    try:
        row = _store.cancel(existing.run_id, binding.tenant_id, str(current_user.user_id), existing.execution_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="managed lifecycle store unavailable") from exc
    if row is None:
        raise HTTPException(status_code=404, detail="managed run not found")
    return ManagedRunResponse(**{key: str(row[key]) for key in ("run_id", "execution_id", "tenant_id", "deployment_id", "status", "workflow_id")})


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
    if existing.status == "cancelled":
        raise HTTPException(status_code=409, detail="cancelled execution cannot be approved")
    owner_subject_id = _store.owner(existing.run_id, existing.tenant_id)
    if owner_subject_id is None:
        raise HTTPException(status_code=404, detail="managed run not found")
    if owner_subject_id == str(current_user.user_id):
        raise HTTPException(status_code=403, detail="approval requires a distinct authorized approver")
    if not body.action or not body.resource or not body.argument_digest:
        raise HTTPException(status_code=422, detail="approval binding is incomplete")
    approval_digest = hashlib.sha256(json.dumps({
        "execution_id": existing.execution_id,
        "action": body.action,
        "resource": body.resource,
        "argument_digest": body.argument_digest,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _authority.approve_execution(
        existing.execution_id,
        approval_digest=approval_digest,
        action=body.action,
        resource=body.resource,
        argument_digest=body.argument_digest,
    )
    try:
        approved = _store.approve(
            run_id=existing.run_id,
            tenant_id=existing.tenant_id,
            owner_subject_id=owner_subject_id,
            execution_id=existing.execution_id,
            approver_subject_id=str(current_user.user_id),
            action=body.action,
            resource=body.resource,
            argument_digest=body.argument_digest,
            policy_version=approver_binding.policy_version,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="managed approval store unavailable") from exc
    if approved is None:
        raise HTTPException(status_code=404, detail="managed run not found")
    return ManagedRunResponse(**{key: str(approved[key]) for key in ("run_id", "execution_id", "tenant_id", "deployment_id", "status", "workflow_id")})


@router.post("/{run_id}/resume", response_model=ManagedRunResponse, status_code=status.HTTP_202_ACCEPTED)
async def resume_managed_run(run_id: str, current_user: User = Depends(get_current_user)) -> ManagedRunResponse:
    _require_managed_profile()
    existing = _owned_run(run_id, current_user)
    binding = _resolver.resolve(current_user, None)
    envelope_data = _store.envelope(existing.run_id, binding.tenant_id, str(current_user.user_id))
    envelope = None if envelope_data is None else QueueEnvelope.from_dict(envelope_data)
    if envelope is None:
        raise HTTPException(status_code=503, detail="managed admission state is unavailable")
    try:
        resumed_envelope = _authority.reissue(envelope, reason="resume")
        job = build_resume_job(
            run_id=existing.run_id,
            run_kind="investigate",
            enqueued_by=str(current_user.user_id),
            tenant_id=existing.tenant_id,
            managed_envelope=resumed_envelope.as_dict(),
        )
        # This endpoint is deliberately async so success means the durable queue
        # accepted the signed resume, not merely that API-local state changed.
        await enqueue_run(job)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="managed run queue unavailable") from exc
    resumed = _store.update_status(existing.run_id, binding.tenant_id, str(current_user.user_id), "queued")
    if resumed is None:
        raise HTTPException(status_code=404, detail="managed run not found")
    return ManagedRunResponse(**{key: str(resumed[key]) for key in ("run_id", "execution_id", "tenant_id", "deployment_id", "status", "workflow_id")})
