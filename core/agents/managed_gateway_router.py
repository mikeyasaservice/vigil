"""Independent managed capability gateway.

Workers present an execution-bound grant and attestation here. The legacy
shared-token tool route is intentionally not accepted by this endpoint.
"""

from __future__ import annotations

import os
import json
import hmac
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from core.agents.managed_execution import Invocation, ManagedSecurityError, QueueEnvelope, ToolGrant
from core.agents.integration_tools import resolve_integration_call
from core.agents.mcp_tools import MCPFailure
from core.agents.managed_service import authority
from core.agents.managed_store import ManagedRunStore
from core.agents.tools_router import Bounds, InvokeRequest, _errored, _failure, _rows, _run
from core.deps import provide_mcp_registry
from core.llm.tool_schemas import CALL_INTEGRATION_TOOL
from core.routing import Auth, RouterMeta

router = APIRouter()
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


class ManagedAuthorizeRequest(BaseModel):
    execution_id: str
    tenant_id: str
    deployment_id: str
    worker_key_id: str = Field(min_length=1)
    claim_token: str = Field(min_length=1)
    attestation: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    grant: Optional[ManagedGrantPayload] = None
    max_rows: int = Field(default=100, gt=0)
    timeout_ms: int = Field(default=30_000, gt=0)


class ManagedClaimRequest(BaseModel):
    envelope: Dict[str, Any]
    worker_key_id: str = Field(min_length=1)
    capabilities: list[str] = Field(default_factory=list)


def _require_client_cert(worker_key_id: str, presented: Optional[str]) -> None:
    if os.getenv("VIGIL_EXECUTION_PROFILE", "standalone").lower() != "managed":
        raise HTTPException(status_code=404, detail="managed gateway is disabled")
    if not presented:
        raise HTTPException(status_code=401, detail="managed gateway requires mTLS client identity")
    raw = os.getenv("VIGIL_MANAGED_WORKER_CERTS", "")
    if not raw:
        raise HTTPException(status_code=503, detail="managed worker certificate trust is unavailable")
    try:
        trusted = json.loads(raw)
        expected = str(trusted[worker_key_id])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=403, detail="managed worker certificate is not authorized") from exc
    if not hmac.compare_digest(expected, presented):
        raise HTTPException(status_code=403, detail="managed worker certificate is not authorized")


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


@router.post("/authorize")
async def authorize_managed_call(
    body: ManagedAuthorizeRequest,
    request: Request,
    x_vigil_client_cert: Optional[str] = Header(default=None),
    registry=Depends(provide_mcp_registry),
) -> Dict[str, Any]:
    _require_client_cert(body.worker_key_id, x_vigil_client_cert)
    if body.grant is not None and body.execution_id != body.grant.execution_id:
        raise HTTPException(status_code=403, detail="grant execution does not match request")
    if body.grant is not None and (body.tenant_id != body.grant.tenant_id or body.deployment_id != body.grant.deployment_id):
        raise HTTPException(status_code=403, detail="grant tenant does not match request")
    if body.grant is not None and body.worker_key_id != body.grant.workload_key_id:
        raise HTTPException(status_code=403, detail="grant workload does not match request")
    try:
        if not ManagedRunStore().claim_active(body.execution_id, body.worker_key_id, body.claim_token):
            raise ManagedSecurityError("execution claim is not active")
        identity = authority.executions.get(body.execution_id)
        if identity is None:
            raise ManagedSecurityError("execution is unknown")
        if identity.tenant_id != body.tenant_id or identity.deployment_id != body.deployment_id:
            raise ManagedSecurityError("execution tenant binding is invalid")
        if identity.worker_key_id != body.worker_key_id or identity.jti != body.claim_token:
            raise ManagedSecurityError("execution claim binding is invalid")
        authority.verify_execution_attestation(identity, body.attestation)
        authorized_tool, authorized_args = body.tool, body.args
        if body.tool == CALL_INTEGRATION_TOOL:
            try:
                authorized_tool, authorized_args = resolve_integration_call(registry, body.args)
            except MCPFailure as exc:
                raise ManagedSecurityError("nested integration call is not authorized") from exc
        if body.grant is None:
            resource = str(authorized_args.get("finding_id") or authorized_args.get("id") or authorized_tool)
            grant = authority.grant(
                identity,
                grant_id=str(__import__("uuid").uuid4()),
                action=authorized_tool,
                resource=resource,
                arguments=authorized_args,
                workload_key_id=body.worker_key_id,
            )
        else:
            grant = ToolGrant(**body.grant.model_dump())
        invocation = Invocation(
            invocation_id=str(request.headers.get("X-Vigil-Invocation-ID", "")),
            execution_id=body.execution_id,
            tenant_id=body.tenant_id,
            action=authorized_tool,
            resource=grant.resource,
            arguments=authorized_args,
            grant=grant,
        )
        if not invocation.invocation_id:
            raise ManagedSecurityError("invocation id is required")
        replayed = ManagedRunStore().reserve_invocation(
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
        authority.authorize(invocation)
        result, handled, source = await _run(InvokeRequest(
            # Dispatch the exact normalized call that was authorized. Resolving
            # the generic integration wrapper a second time could otherwise
            # authorize one tool and execute another after registry changes.
            tool=authorized_tool,
            args=authorized_args,
            bounds=Bounds(max_rows=body.max_rows, timeout_ms=body.timeout_ms),
        ), registry)
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed call denied") from exc
    except Exception as exc:  # noqa: BLE001 - gateway never leaks connector details
        raise HTTPException(status_code=503, detail="managed gateway unavailable") from exc
    if not handled:
        response = _failure("refused", detail=f"no such tool: {body.tool}")
    else:
        error = _errored(result)
        if error is not None:
            response = _failure("backend_error", detail=error)
        else:
            rows = _rows(result)
            response = {
                "ok": True,
                "rows": rows[: body.max_rows],
                "rowCount": min(len(rows), body.max_rows),
                "capped": len(rows) > body.max_rows,
                "sourceSystem": source,
            }
    try:
        ManagedRunStore().complete_invocation(invocation.invocation_id, invocation.execution_id, response)
    except Exception as exc:  # noqa: BLE001 - uncertain outcomes are never replayed
        raise HTTPException(status_code=503, detail="managed invocation outcome is uncertain") from exc
    return response


@router.post("/claim")
def claim_managed_execution(
    body: ManagedClaimRequest,
    x_vigil_client_cert: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_client_cert(body.worker_key_id, x_vigil_client_cert)
    try:
        envelope = QueueEnvelope.from_dict(body.envelope)
        deployment_id = os.getenv("VIGIL_DEPLOYMENT_ID", "")
        if not deployment_id:
            raise ManagedSecurityError("managed deployment binding is unavailable")
        if not os.getenv("VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY"):
            raise ManagedSecurityError("managed authority signing key is unavailable")
        identity = authority.claim(
            envelope,
            worker_key_id=body.worker_key_id,
            capabilities=_claim_capabilities(body.capabilities),
            deployment_id=deployment_id,
        )
        ManagedRunStore().record_claim(identity.execution_id, identity.worker_key_id, identity.jti, identity.expires_at)
    except ManagedSecurityError as exc:
        raise HTTPException(status_code=403, detail="managed claim denied") from exc
    return {
        "execution_id": identity.execution_id,
        "tenant_id": identity.tenant_id,
        "deployment_id": identity.deployment_id,
        "workflow_id": identity.workflow_id,
        "workflow_digest": identity.workflow_digest,
        "program_id": identity.program_id,
        "program_digest": identity.program_digest,
        "worker_key_id": identity.worker_key_id,
        "attestation": authority.sign_execution_attestation(identity),
        "jti": identity.jti,
        "capabilities": list(identity.capabilities),
        "policy_version": identity.policy_version,
        "revocation_epoch": identity.revocation_epoch,
        "expires_at": identity.expires_at.isoformat(),
    }
