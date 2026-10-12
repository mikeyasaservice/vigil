"""Independent managed capability gateway.

Workers present an execution-bound grant and attestation here. The legacy
shared-token tool route is intentionally not accepted by this endpoint.
"""

from __future__ import annotations

import logging
import os
import hmac
import uuid
import httpx
from datetime import datetime, timedelta
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from core.agents.managed_execution import (
    ExecutionIdentity,
    Invocation,
    ManagedSecurityError,
    QueueEnvelope,
    ToolGrant,
    managed_digest,
)
from core.agents.integration_tools import resolve_integration_call
from core.agents.mcp_tools import MCPFailure
from core.agents.managed_service import authority
from core.agents.managed_store import ManagedRunStore
from core.deps import provide_mcp_registry
from core.llm.tool_schemas import CALL_INTEGRATION_TOOL
from core.routing import Auth, RouterMeta

router = APIRouter()
logger = logging.getLogger(__name__)
ROUTER_META = RouterMeta(
    prefix="/v1",
    tags=["managed-gateway"],
    auth=Auth.ROUTER_MANAGED,
    reason="Tenant-local capability gateway; mTLS and execution-bound grants are required.",
)


class ManagedGrantPayload(BaseModel):
    grant_id: str
    execution_id: str
    tenant_id: str
    deployment_id: str
    deployment_incarnation: str
    workflow_id: str
    workflow_digest: str
    program_id: str
    program_digest: str
    action: str
    resource: str
    argument_digest: str
    approval_digest: Optional[str] = None
    policy_version: str
    revocation_epoch: int
    issued_at: datetime
    expires_at: datetime
    workload_key_id: str
    claim_jti: str
    max_rows: int = Field(gt=0)
    timeout_ms: int = Field(gt=0)
    signature: str = Field(min_length=1)


class ManagedGrantRequest(BaseModel):
    execution_id: str
    tenant_id: str
    deployment_id: str
    # Compatibility echo only. Authorization uses the SPIFFE identity supplied
    # by the trusted local identity proxy, never this request field.
    worker_key_id: Optional[str] = None
    claim_token: str = Field(min_length=1)
    attestation: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    max_rows: int = Field(default=100, gt=0)
    timeout_ms: int = Field(default=30_000, gt=0)


class ManagedAuthorizeRequest(ManagedGrantRequest):
    grant: ManagedGrantPayload


class ManagedClaimRequest(BaseModel):
    envelope: Dict[str, Any]
    capabilities: list[str] = Field(default_factory=list)


class ManagedStatusRequest(BaseModel):
    execution_id: str
    claim_token: str = Field(min_length=1)
    attestation: str = Field(min_length=1)
    status: Literal["running", "retrying", "waiting_approval", "succeeded", "failed"]
    pending: Optional["ManagedPendingApproval"] = None


class ManagedPendingApproval(BaseModel):
    checkpoint_id: str = Field(min_length=1, max_length=200)
    tool: str = Field(min_length=1, max_length=200)
    args: str = Field(min_length=2, max_length=100_000)


class ManagedDecisionsRequest(BaseModel):
    execution_id: str = Field(min_length=1)
    claim_token: str = Field(min_length=1)
    attestation: str = Field(min_length=1)


ManagedStatusRequest.model_rebuild()


def _require_spiffe_workload(
    request: Request,
    presented_id: Optional[str],
    proxy_token: Optional[str],
) -> str:
    """Return identity asserted by the local SPIRE/Envoy boundary.

    The application listener is private to the security pod. Envoy terminates
    SPIFFE mTLS, strips these headers from the downstream request, and adds its
    verified URI SAN plus a pod-local proxy token on the Unix-socket hop.
    """
    if os.getenv("VIGIL_EXECUTION_PROFILE", "standalone").lower() != "managed":
        raise HTTPException(status_code=404, detail="managed gateway is disabled")
    scoped = request.scope.get("vigil.verified_spiffe_id")
    if isinstance(scoped, str) and scoped:
        workload_id = scoped
    else:
        expected_token = os.getenv("VIGIL_IDENTITY_PROXY_TOKEN", "")
        if not expected_token:
            raise HTTPException(status_code=503, detail="managed identity proxy trust is unavailable")
        if not proxy_token or not hmac.compare_digest(expected_token, proxy_token):
            raise HTTPException(status_code=401, detail="managed gateway requires verified workload identity")
        workload_id = presented_id or ""
    expected_id = os.getenv("VIGIL_WORKER_SPIFFE_ID", "")
    if not workload_id or not expected_id:
        raise HTTPException(status_code=503, detail="managed SPIFFE policy is unavailable")
    if not hmac.compare_digest(expected_id, workload_id):
        raise HTTPException(status_code=403, detail="managed workload is not authorized")
    return workload_id


def _claim_capabilities(requested: list[str]) -> tuple[str, ...]:
    configured = {
        value.strip()
        for value in os.getenv("VIGIL_MANAGED_CAPABILITIES", "").split(",")
        if value.strip()
    }
    if not configured:
        raise ManagedSecurityError("managed capability policy is unavailable")
    requested_set = set(requested)
    if requested_set and not requested_set.issubset(configured):
        raise ManagedSecurityError("worker requested capabilities outside policy")
    return tuple(sorted(requested_set or configured))


def _load_execution(
    store: ManagedRunStore,
    body: ManagedGrantRequest,
    workload_id: str,
) -> ExecutionIdentity:
    if body.worker_key_id is not None and body.worker_key_id != workload_id:
        raise ManagedSecurityError("request workload binding is invalid")
    held = store.authorization_context(body.execution_id, workload_id, body.claim_token)
    if held is None:
        raise ManagedSecurityError("execution claim is not active")
    raw_capabilities = held["capabilities"]
    if isinstance(raw_capabilities, str):
        raw_capabilities = __import__("json").loads(raw_capabilities)
    identity = ExecutionIdentity(
        execution_id=str(held["execution_id"]),
        tenant_id=str(held["tenant_id"]),
        deployment_id=str(held["deployment_id"]),
        deployment_incarnation=str(held["deployment_incarnation"]),
        worker_key_id=workload_id,
        workflow_id=str(held["workflow_id"]),
        workflow_digest=str(held["workflow_digest"]),
        program_id=str(held["program_id"]),
        program_digest=str(held["program_digest"]),
        capabilities=tuple(str(value) for value in raw_capabilities),
        policy_version=str(held["policy_version"]),
        revocation_epoch=int(held["revocation_epoch"]),
        issued_at=held["issued_at"],
        expires_at=held["expires_at"],
        jti=str(held["jti"]),
    )
    if identity.tenant_id != body.tenant_id or identity.deployment_id != body.deployment_id:
        raise ManagedSecurityError("execution tenant binding is invalid")
    if identity.jti != body.claim_token:
        raise ManagedSecurityError("execution claim binding is invalid")
    authority.verify_execution_attestation(identity, body.attestation)
    return identity


def _normalize_call(registry: Any, tool: str, args: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    if tool != CALL_INTEGRATION_TOOL:
        return tool, args
    try:
        return resolve_integration_call(registry, args)
    except MCPFailure as exc:
        raise ManagedSecurityError("nested integration call is not authorized") from exc


def _resource_for(tool: str, args: Dict[str, Any]) -> str:
    return str(args.get("finding_id") or args.get("id") or tool)


def _binding_for(
    store: ManagedRunStore,
    identity: ExecutionIdentity,
    tool: str,
    resource: str,
    argument_digest: str,
) -> Optional[str]:
    if tool not in identity.capabilities:
        raise ManagedSecurityError("action is outside the claimed capability set")
    approval_actions = {
        value.strip()
        for value in os.getenv("VIGIL_MANAGED_APPROVAL_ACTIONS", "").split(",")
        if value.strip()
    }
    if tool in approval_actions and not store.approval_active(
        execution_id=identity.execution_id,
        action=tool,
        resource=resource,
        argument_digest=argument_digest,
        policy_version=identity.policy_version,
    ):
        raise ManagedSecurityError("managed call requires an active approval")
    builtins = {
        value.strip()
        for value in os.getenv("VIGIL_MANAGED_BUILTIN_TOOLS", "").split(",")
        if value.strip()
    }
    if not builtins:
        raise ManagedSecurityError("managed builtin tool policy is unavailable")
    binding_id = None if tool in builtins else store.integration_binding(identity.tenant_id, tool)
    if tool not in builtins and binding_id is None:
        raise ManagedSecurityError("integration is not owned by this tenant")
    return binding_id


def _denial_code(error: ManagedSecurityError) -> str:
    message = str(error)
    for fragment, code in (
        ("capability", "capability_denied"),
        ("approval", "approval_required"),
        ("integration", "integration_not_owned"),
        ("budget", "budget_denied"),
        ("invocation id", "invocation_conflict"),
        ("invocation outcome", "invocation_unresolved"),
        ("signature", "grant_invalid"),
        ("grant", "grant_invalid"),
        ("claim", "claim_invalid"),
        ("tenant", "tenant_binding_invalid"),
    ):
        if fragment in message:
            return code
    return "policy_denied"


def _record_denial(
    store: ManagedRunStore,
    identity: Optional[ExecutionIdentity],
    *,
    action: str,
    resource: str,
    arguments: Dict[str, Any],
    error: ManagedSecurityError,
) -> None:
    if identity is None:
        return
    try:
        store.record_authorization_denial(
            execution_id=identity.execution_id,
            tenant_id=identity.tenant_id,
            action=action or "unknown",
            resource=resource or "unknown",
            argument_digest=managed_digest(arguments),
            reason_code=_denial_code(error),
        )
    except Exception:  # noqa: BLE001 - audit failure cannot turn a denial into access
        logger.exception("managed denial audit unavailable")


async def _connector_dispatch(
    *, tool: str, args: Dict[str, Any], tenant_id: str, execution_id: str,
    binding_id: Optional[str], max_rows: int, timeout_ms: int, invocation_id: str,
) -> Dict[str, Any]:
    url = os.getenv("VIGIL_CONNECTOR_URL", "http://127.0.0.1:15003/v1/invoke")
    timeout = max(1.0, timeout_ms / 1000 + 1.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url, headers={"X-Vigil-Invocation-ID": invocation_id}, json={
            "tool": tool, "args": args, "tenant_id": tenant_id,
            "execution_id": execution_id, "binding_id": binding_id,
            "max_rows": max_rows, "timeout_ms": timeout_ms,
        })
    if response.status_code != 200:
        raise ManagedSecurityError("managed connector denied or failed")
    value = response.json()
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        raise ManagedSecurityError("managed connector returned an invalid result")
    return value


@router.post("/grants")
def issue_managed_grant(
    body: ManagedGrantRequest,
    request: Request,
    x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
    x_vigil_identity_proxy_token: Optional[str] = Header(default=None),
    registry=Depends(provide_mcp_registry),
) -> Dict[str, Any]:
    workload_id = _require_spiffe_workload(
        request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token
    )
    store = ManagedRunStore()
    identity: Optional[ExecutionIdentity] = None
    tool, arguments = body.tool, body.args
    resource = _resource_for(tool, arguments)
    try:
        identity = _load_execution(store, body, workload_id)
        tool, arguments = _normalize_call(registry, body.tool, body.args)
        resource = _resource_for(tool, arguments)
        argument_digest = managed_digest(arguments)
        _binding_for(store, identity, tool, resource, argument_digest)
        now = datetime.now(identity.expires_at.tzinfo)
        unsigned = ToolGrant(
            grant_id=str(uuid.uuid4()),
            execution_id=identity.execution_id,
            tenant_id=identity.tenant_id,
            deployment_id=identity.deployment_id,
            deployment_incarnation=identity.deployment_incarnation,
            workflow_id=identity.workflow_id,
            workflow_digest=identity.workflow_digest,
            program_id=identity.program_id,
            program_digest=identity.program_digest,
            action=tool,
            resource=resource,
            argument_digest=argument_digest,
            approval_digest=None,
            policy_version=identity.policy_version,
            revocation_epoch=identity.revocation_epoch,
            issued_at=now,
            expires_at=min(identity.expires_at, now + timedelta(seconds=60)),
            workload_key_id=workload_id,
            claim_jti=identity.jti,
            max_rows=body.max_rows,
            timeout_ms=body.timeout_ms,
        )
        return authority.sign_tool_grant(unsigned).as_dict()
    except ManagedSecurityError as exc:
        _record_denial(
            store, identity, action=tool, resource=resource,
            arguments=arguments, error=exc,
        )
        raise HTTPException(status_code=403, detail="managed grant denied") from exc
    except Exception as exc:  # noqa: BLE001 - grant failures do not leak trusted state
        raise HTTPException(status_code=503, detail="managed grant authority unavailable") from exc


@router.post("/authorize")
async def authorize_managed_call(
    body: ManagedAuthorizeRequest,
    request: Request,
    x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
    x_vigil_identity_proxy_token: Optional[str] = Header(default=None),
    registry=Depends(provide_mcp_registry),
) -> Dict[str, Any]:
    workload_id = _require_spiffe_workload(
        request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token
    )
    store = ManagedRunStore()
    identity: Optional[ExecutionIdentity] = None
    tool, arguments = body.tool, body.args
    resource = _resource_for(tool, arguments)
    try:
        identity = _load_execution(store, body, workload_id)
        tool, arguments = _normalize_call(registry, body.tool, body.args)
        resource = _resource_for(tool, arguments)
        grant = ToolGrant(**body.grant.model_dump())
        authority.verify_tool_grant(grant)
        if grant.execution_id != identity.execution_id:
            raise ManagedSecurityError("grant execution does not match request")
        if grant.tenant_id != identity.tenant_id or grant.deployment_id != identity.deployment_id:
            raise ManagedSecurityError("grant tenant does not match request")
        if grant.deployment_incarnation != identity.deployment_incarnation:
            raise ManagedSecurityError("grant deployment incarnation does not match request")
        if (
            grant.workflow_id != identity.workflow_id
            or grant.workflow_digest != identity.workflow_digest
            or grant.program_id != identity.program_id
            or grant.program_digest != identity.program_digest
        ):
            raise ManagedSecurityError("grant workflow or program does not match request")
        if grant.workload_key_id != workload_id or grant.claim_jti != identity.jti:
            raise ManagedSecurityError("grant belongs to a fenced claim")
        if grant.action != tool or grant.resource != resource:
            raise ManagedSecurityError("grant action or resource is invalid")
        if grant.argument_digest != managed_digest(arguments):
            raise ManagedSecurityError("grant arguments are invalid")
        if grant.policy_version != identity.policy_version or grant.revocation_epoch != identity.revocation_epoch:
            raise ManagedSecurityError("grant policy is stale")
        if grant.max_rows != body.max_rows or grant.timeout_ms != body.timeout_ms:
            raise ManagedSecurityError("grant bounds are invalid")
        invocation = Invocation(
            invocation_id=str(request.headers.get("X-Vigil-Invocation-ID", "")),
            execution_id=body.execution_id,
            tenant_id=body.tenant_id,
            action=tool,
            resource=resource,
            arguments=arguments,
            grant=grant,
            max_rows=body.max_rows,
            timeout_ms=body.timeout_ms,
        )
        if not invocation.invocation_id:
            raise ManagedSecurityError("invocation id is required")
        binding_id = _binding_for(
            store, identity, tool, resource, invocation.argument_digest
        )
        replayed = store.reserve_invocation(
            invocation_id=invocation.invocation_id,
            execution_id=invocation.execution_id,
            tenant_id=invocation.tenant_id,
            action=invocation.action,
            resource=invocation.resource,
            argument_digest=invocation.argument_digest,
            reserved_units=invocation.budget_units,
        )
        if replayed is not None:
            return replayed
        response = await _connector_dispatch(
            tool=tool,
            args=arguments,
            tenant_id=identity.tenant_id,
            execution_id=identity.execution_id,
            binding_id=binding_id,
            max_rows=body.max_rows,
            timeout_ms=body.timeout_ms,
            invocation_id=invocation.invocation_id,
        )
    except ManagedSecurityError as exc:
        _record_denial(
            store, identity, action=tool, resource=resource,
            arguments=arguments, error=exc,
        )
        raise HTTPException(status_code=403, detail="managed call denied") from exc
    except Exception as exc:  # noqa: BLE001 - gateway never leaks connector details
        raise HTTPException(status_code=503, detail="managed gateway unavailable") from exc
    try:
        ManagedRunStore().complete_invocation(invocation.invocation_id, invocation.execution_id, response)
    except Exception as exc:  # noqa: BLE001 - uncertain outcomes are never replayed
        raise HTTPException(status_code=503, detail="managed invocation outcome is uncertain") from exc
    return response


@router.post("/claim")
def claim_managed_execution(
    body: ManagedClaimRequest,
    request: Request,
    x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
    x_vigil_identity_proxy_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    workload_id = _require_spiffe_workload(
        request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token
    )
    try:
        envelope = QueueEnvelope.from_dict(body.envelope)
        deployment_id = os.getenv("VIGIL_DEPLOYMENT_ID", "")
        deployment_incarnation = os.getenv("VIGIL_DEPLOYMENT_INCARNATION", "")
        if not deployment_id or not deployment_incarnation:
            raise ManagedSecurityError("managed deployment binding is unavailable")
        if not os.getenv("VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY"):
            raise ManagedSecurityError("managed authority signing key is unavailable")
        identity = authority.claim(
            envelope,
            worker_key_id=workload_id,
            capabilities=_claim_capabilities(body.capabilities),
            deployment_id=deployment_id,
            deployment_incarnation=deployment_incarnation,
        )
    except ManagedSecurityError as exc:
        logger.warning(
            "managed claim authority denied: %s",
            exc,
            extra={"denial_code": "claim_authority_denied"},
        )
        raise HTTPException(
            status_code=403,
            detail={"code": "claim_authority_denied"},
        ) from exc
    try:
        ManagedRunStore().record_claim(envelope, identity)
    except ManagedSecurityError as exc:
        logger.warning(
            "managed claim durable state denied: %s",
            exc,
            extra={"denial_code": "claim_state_denied"},
        )
        raise HTTPException(
            status_code=403,
            detail={"code": "claim_state_denied"},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - details stay in tenant-local logs
        logger.exception("managed claim persistence unavailable")
        raise HTTPException(
            status_code=503,
            detail={"code": "claim_state_unavailable"},
        ) from exc
    return {
        "execution_id": identity.execution_id,
        "tenant_id": identity.tenant_id,
        "deployment_id": identity.deployment_id,
        "deployment_incarnation": identity.deployment_incarnation,
        "workflow_id": identity.workflow_id,
        "workflow_digest": identity.workflow_digest,
        "program_id": identity.program_id,
        "program_digest": identity.program_digest,
        "worker_key_id": identity.worker_key_id,
        "workload_spiffe_id": workload_id,
        "attestation": authority.sign_execution_attestation(identity),
        "jti": identity.jti,
        "capabilities": list(identity.capabilities),
        "policy_version": identity.policy_version,
        "revocation_epoch": identity.revocation_epoch,
        "issued_at": identity.issued_at.isoformat(),
        "expires_at": identity.expires_at.isoformat(),
    }


@router.post("/status")
def update_managed_execution_status(
    body: ManagedStatusRequest,
    request: Request,
    x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
    x_vigil_identity_proxy_token: Optional[str] = Header(default=None),
    registry=Depends(provide_mcp_registry),
) -> Dict[str, Any]:
    workload_id = _require_spiffe_workload(
        request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token
    )
    try:
        store = ManagedRunStore()
        held = store.authorization_context(body.execution_id, workload_id, body.claim_token)
        if held is None:
            raise ManagedSecurityError("execution claim is not active")
        raw_capabilities = held["capabilities"]
        if isinstance(raw_capabilities, str):
            raw_capabilities = __import__("json").loads(raw_capabilities)
        from core.agents.managed_execution import ExecutionIdentity

        identity = ExecutionIdentity(
            execution_id=str(held["execution_id"]), tenant_id=str(held["tenant_id"]),
            deployment_id=str(held["deployment_id"]),
            deployment_incarnation=str(held["deployment_incarnation"]), worker_key_id=workload_id,
            workflow_id=str(held["workflow_id"]), workflow_digest=str(held["workflow_digest"]),
            program_id=str(held["program_id"]), program_digest=str(held["program_digest"]),
            capabilities=tuple(str(value) for value in raw_capabilities),
            policy_version=str(held["policy_version"]), revocation_epoch=int(held["revocation_epoch"]),
            issued_at=held["issued_at"], expires_at=held["expires_at"], jti=str(held["jti"]),
        )
        authority.verify_execution_attestation(identity, body.attestation)
        pending = None
        if body.status == "waiting_approval":
            if body.pending is None:
                raise ManagedSecurityError("waiting execution omitted its pending action")
            try:
                arguments = __import__("json").loads(body.pending.args)
            except (TypeError, ValueError) as exc:
                raise ManagedSecurityError("pending approval arguments are invalid") from exc
            if not isinstance(arguments, dict):
                raise ManagedSecurityError("pending approval arguments are invalid")
            action, normalized = body.pending.tool, arguments
            if action == CALL_INTEGRATION_TOOL:
                try:
                    action, normalized = resolve_integration_call(registry, arguments)
                except MCPFailure as exc:
                    raise ManagedSecurityError("pending nested integration is invalid") from exc
            if action not in identity.capabilities:
                raise ManagedSecurityError("pending action is outside the claimed capability set")
            resource = str(normalized.get("finding_id") or normalized.get("id") or action)
            pending = {
                "checkpoint_id": body.pending.checkpoint_id,
                "action": action,
                "resource": resource,
                "argument_digest": managed_digest(normalized),
            }
        if not store.update_execution_status(
            execution_id=identity.execution_id,
            workload_spiffe_id=workload_id,
            claim_token=identity.jti,
            status=body.status,
            pending_approval=pending,
        ):
            raise ManagedSecurityError("execution status update was fenced")
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed status update denied") from exc
    except Exception as exc:  # noqa: BLE001 - never expose trusted state failures
        raise HTTPException(status_code=503, detail="managed status authority unavailable") from exc
    return {"execution_id": identity.execution_id, "status": body.status}


@router.post("/decisions")
def list_managed_execution_decisions(
    body: ManagedDecisionsRequest,
    request: Request,
    x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
    x_vigil_identity_proxy_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    workload_id = _require_spiffe_workload(
        request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token
    )
    try:
        store = ManagedRunStore()
        held = store.authorization_context(body.execution_id, workload_id, body.claim_token)
        if held is None:
            raise ManagedSecurityError("execution claim is not active")
        raw_capabilities = held["capabilities"]
        if isinstance(raw_capabilities, str):
            raw_capabilities = __import__("json").loads(raw_capabilities)
        from core.agents.managed_execution import ExecutionIdentity

        identity = ExecutionIdentity(
            execution_id=str(held["execution_id"]), tenant_id=str(held["tenant_id"]),
            deployment_id=str(held["deployment_id"]),
            deployment_incarnation=str(held["deployment_incarnation"]), worker_key_id=workload_id,
            workflow_id=str(held["workflow_id"]), workflow_digest=str(held["workflow_digest"]),
            program_id=str(held["program_id"]), program_digest=str(held["program_digest"]),
            capabilities=tuple(str(value) for value in raw_capabilities),
            policy_version=str(held["policy_version"]), revocation_epoch=int(held["revocation_epoch"]),
            issued_at=held["issued_at"], expires_at=held["expires_at"], jti=str(held["jti"]),
        )
        authority.verify_execution_attestation(identity, body.attestation)
        rows = store.approved_decisions(
            execution_id=body.execution_id,
            workload_spiffe_id=workload_id,
            claim_token=body.claim_token,
        )
        if rows is None:
            raise ManagedSecurityError("execution decisions are fenced")
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed decisions denied") from exc
    return {
        "decisions": [
            {
                "checkpoint_id": str(row["checkpoint_id"]),
                "actor": str(row["approver_subject_id"]),
                "answer": "approve",
                "text": "",
                "resolved_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }
