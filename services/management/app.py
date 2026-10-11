from __future__ import annotations

from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from services.management.auth import OperatorIdentity, current_operator
from services.management.commands import issue_reconcile_command
from services.management.contracts import (
    OperationApproval,
    OperationFailure,
    OperationReceipt,
    OperationRequest,
    PlanReadyRequest,
    ReconcileClaimRequest,
)
from services.management.store import (
    ManagementConflict,
    ManagementDenied,
    ManagementError,
    ManagementStore,
    ManagementUnavailable,
)


app = FastAPI(title="Vigil management plane", version="3.0.0")


def _store() -> ManagementStore:
    return ManagementStore()


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, ManagementDenied):
        return HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)})
    if isinstance(exc, ManagementConflict):
        return HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)})
    if isinstance(exc, (ManagementUnavailable, RuntimeError)):
        return HTTPException(status_code=503, detail={"code": getattr(exc, "code", "management_unavailable"), "message": str(exc)})
    return HTTPException(status_code=422, detail={"code": getattr(exc, "code", "management_invalid"), "message": str(exc)})


def _serializable(row: dict) -> dict:
    return {key: value.isoformat() if isinstance(value, datetime) else str(value) if key == "operation_id" else value for key, value in row.items()}


def _reconciler_identity(request: Request) -> str:
    scoped = request.scope.get("vigil.verified_spiffe_id")
    if isinstance(scoped, str) and scoped:
        return scoped
    tls = request.scope.get("extensions", {}).get("tls", {})
    chain = tls.get("client_cert_chain", ())
    if not chain:
        raise HTTPException(status_code=401, detail="verified reconciler client certificate required")
    try:
        certificate = x509.load_pem_x509_certificate(chain[0].encode())
        sans = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        identities = [
            str(uri)
            for uri in sans.get_values_for_type(x509.UniformResourceIdentifier)
            if str(uri).startswith("spiffe://")
        ]
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise HTTPException(status_code=401, detail="reconciler client certificate identity is invalid") from exc
    if len(identities) != 1:
        raise HTTPException(status_code=401, detail="reconciler client certificate must contain one SPIFFE URI")
    return identities[0]


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
@app.get("/healthz", include_in_schema=False)
def readyz() -> dict[str, str]:
    try:
        _store().check_ready()
    except ManagementUnavailable as exc:
        raise _error(exc) from exc
    return {"status": "ok"}


@app.post("/v1/deployments/{deployment_id}/operations", status_code=202)
def request_operation(
    deployment_id: str,
    body: OperationRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    if deployment_id != body.manifest.deployment_id:
        raise HTTPException(status_code=409, detail={"code": "management_conflict", "message": "path deployment does not match manifest"})
    try:
        return _serializable(_store().submit_operation(body.manifest, body.operation_kind, idempotency_key or "", actor))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/deployments/{deployment_id}")
def get_deployment(deployment_id: str, actor: OperatorIdentity = Depends(current_operator)) -> dict:
    try:
        row = _store().get_deployment(deployment_id, actor)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="deployment not found")
    return _serializable(row)


@app.get("/v1/operations/{operation_id}")
def get_operation(operation_id: str, actor: OperatorIdentity = Depends(current_operator)) -> dict:
    try:
        row = _store().get_operation(operation_id, actor)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="operation not found")
    return _serializable(row)


@app.post("/v1/operations/{operation_id}/approve")
def approve_operation(
    operation_id: str,
    body: OperationApproval,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        expiry = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        row = _store().approve_operation(operation_id, actor, body.manifest_digest, body.plan_hash, expiry)
        return _serializable(row)
    except (ValueError, ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/operations/{operation_id}/cancel")
def cancel_operation(operation_id: str, actor: OperatorIdentity = Depends(current_operator)) -> dict:
    try:
        return _serializable(_store().cancel_operation(operation_id, actor))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/internal/v1/operations/{operation_id}/claim")
def claim_reconcile(
    operation_id: str,
    body: ReconcileClaimRequest,
    request: Request,
) -> dict:
    workload = _reconciler_identity(request)
    try:
        operation, manifest = _store().claim_reconcile(operation_id, workload, body.runner_id, body.phase)
        signed = issue_reconcile_command(operation, manifest, body.phase)
        return {**signed, "manifest": manifest}
    except (ManagementError, ManagementUnavailable, RuntimeError) as exc:
        raise _error(exc) from exc


@app.post("/internal/v1/operations/{operation_id}/plan-ready")
def plan_ready(
    operation_id: str,
    body: PlanReadyRequest,
    request: Request,
    runner_id: str = Header(alias="X-Vigil-Runner-Id"),
) -> dict:
    workload = _reconciler_identity(request)
    try:
        return _serializable(
            _store().record_plan(
                operation_id,
                workload,
                runner_id,
                str(body.command_id),
                body.fencing_token,
                body.manifest_digest,
                body.plan_hash,
            )
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/internal/v1/operations/{operation_id}/fail")
def fail_operation(
    operation_id: str,
    body: OperationFailure,
    request: Request,
    runner_id: str = Header(alias="X-Vigil-Runner-Id"),
) -> dict:
    workload = _reconciler_identity(request)
    try:
        return _serializable(
            _store().fail_operation(
                operation_id,
                workload,
                runner_id,
                str(body.command_id),
                body.fencing_token,
                body.phase,
                body.error_code,
                body.error_detail,
            )
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/internal/v1/operations/{operation_id}/complete")
def complete_operation(
    operation_id: str,
    body: OperationReceipt,
    request: Request,
    runner_id: str = Header(alias="X-Vigil-Runner-Id"),
) -> dict:
    workload = _reconciler_identity(request)
    try:
        receipt = body.model_dump(mode="json")
        return _serializable(_store().complete_operation(operation_id, workload, runner_id, receipt))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
