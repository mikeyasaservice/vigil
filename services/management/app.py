from __future__ import annotations

import uuid
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from services.management.auth import OperatorIdentity, current_operator
from services.management.byoc import enrollment_material, issue_connector_certificate
from services.management.commands import issue_reconcile_command
from services.management.contracts import (
    BYOCCertificateResponse,
    BYOCCertificateRotationRequest,
    BYOCConnectorResponse,
    BYOCEnrollmentCompleteResponse,
    BYOCEnrollmentRequest,
    BYOCEnrollmentResponse,
    BYOCEnrollRequest,
    BYOCHealthEvent,
    BYOCHealthReceipt,
    FederatedSessionResponse,
    IdentityProviderRequest,
    OperationApproval,
    OperationFailure,
    OperationReceipt,
    OperationRequest,
    OperatorAccessApproval,
    OperatorAccessAuthorization,
    OperatorAccessDecision,
    OperatorAccessRequest,
    OperatorAccessSessionResponse,
    PlanReadyRequest,
    QuotaCommitRequest,
    QuotaReservationRequest,
    QuotaReservationResponse,
    ReconcileClaimRequest,
    RouteTicketResponse,
    SAMLAssertionRequest,
    SAMLLoginResponse,
    SCIMTokenRequest,
    TenantContextResponse,
    UsageWindowResponse,
)
from services.management.enterprise_identity import EnterpriseIdentityStore
from services.management.operator_access import OperatorAccessStore
from services.management.saas_auth import CustomerIdentity, current_customer
from services.management.saas_tickets import issue_route_ticket
from services.management.store import (
    ManagementConflict,
    ManagementDenied,
    ManagementError,
    ManagementStore,
    ManagementUnavailable,
)

app = FastAPI(title="Autobot Management Plane", version="6.0.0")


def _store() -> ManagementStore:
    return ManagementStore()


def _identity_store() -> EnterpriseIdentityStore:
    return EnterpriseIdentityStore()


def _operator_access_store() -> OperatorAccessStore:
    return OperatorAccessStore()


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, ManagementDenied):
        return HTTPException(
            status_code=403, detail={"code": exc.code, "message": str(exc)}
        )
    if isinstance(exc, ManagementConflict):
        return HTTPException(
            status_code=409, detail={"code": exc.code, "message": str(exc)}
        )
    if isinstance(exc, (ManagementUnavailable, RuntimeError)):
        return HTTPException(
            status_code=503,
            detail={
                "code": getattr(exc, "code", "management_unavailable"),
                "message": str(exc),
            },
        )
    return HTTPException(
        status_code=422,
        detail={
            "code": getattr(exc, "code", "management_invalid"),
            "message": str(exc),
        },
    )


def _serializable(row: dict) -> dict:
    return {
        key: (
            value.isoformat()
            if isinstance(value, datetime)
            else str(value) if isinstance(value, uuid.UUID) else value
        )
        for key, value in row.items()
    }


def _reconciler_identity(request: Request) -> str:
    scoped = request.scope.get("state", {}).get("vigil.verified_spiffe_id")
    if isinstance(scoped, str) and scoped:
        return scoped
    tls = request.scope.get("extensions", {}).get("tls", {})
    chain = tls.get("client_cert_chain", ())
    if not chain:
        raise HTTPException(
            status_code=401, detail="verified reconciler client certificate required"
        )
    try:
        certificate = x509.load_pem_x509_certificate(chain[0].encode())
        sans = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        identities = [
            str(uri)
            for uri in sans.get_values_for_type(x509.UniformResourceIdentifier)
            if str(uri).startswith("spiffe://")
        ]
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise HTTPException(
            status_code=401, detail="reconciler client certificate identity is invalid"
        ) from exc
    if len(identities) != 1:
        raise HTTPException(
            status_code=401,
            detail="reconciler client certificate must contain one SPIFFE URI",
        )
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
        raise HTTPException(
            status_code=409,
            detail={
                "code": "management_conflict",
                "message": "path deployment does not match manifest",
            },
        )
    try:
        return _serializable(
            _store().submit_operation(
                body.manifest, body.operation_kind, idempotency_key or "", actor
            )
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/deployments/{deployment_id}")
def get_deployment(
    deployment_id: str, actor: OperatorIdentity = Depends(current_operator)
) -> dict:
    try:
        row = _store().get_deployment(deployment_id, actor)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="deployment not found")
    return _serializable(row)


@app.get("/v1/operations/{operation_id}")
def get_operation(
    operation_id: str, actor: OperatorIdentity = Depends(current_operator)
) -> dict:
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
        row = _store().approve_operation(
            operation_id, actor, body.manifest_digest, body.plan_hash, expiry
        )
        return _serializable(row)
    except (ValueError, ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/operations/{operation_id}/cancel")
def cancel_operation(
    operation_id: str, actor: OperatorIdentity = Depends(current_operator)
) -> dict:
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
        operation, manifest = _store().claim_reconcile(
            operation_id, workload, body.runner_id, body.phase
        )
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
        return _serializable(
            _store().complete_operation(operation_id, workload, runner_id, receipt)
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/saas/tenants", response_model=list[TenantContextResponse])
def list_saas_tenants(
    actor: CustomerIdentity = Depends(current_customer),
) -> list[dict]:
    try:
        return [_serializable(row) for row in _store().list_saas_contexts(actor)]
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/saas/tenants/{tenant_id}/route", response_model=RouteTicketResponse)
def create_saas_route(
    tenant_id: str, actor: CustomerIdentity = Depends(current_customer)
) -> dict:
    try:
        store = _store()
        route = store.resolve_saas_route(tenant_id, actor)
        ticket, ticket_id, expires_at = issue_route_ticket(route, actor)
        store.record_route_ticket(ticket_id, route, actor, expires_at)
        return {
            "ticket": ticket,
            "expires_at": expires_at.isoformat(),
            "tenant_id": route["tenant_id"],
            "deployment_id": route["deployment_id"],
            "cell_id": route["cell_id"],
        }
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/saas/tenants/{tenant_id}/usage", response_model=list[UsageWindowResponse])
def get_saas_usage(
    tenant_id: str, actor: CustomerIdentity = Depends(current_customer)
) -> list[dict]:
    try:
        return [_serializable(row) for row in _store().list_usage(tenant_id, actor)]
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post(
    "/internal/v1/saas/deployments/{deployment_id}/quota/reservations",
    response_model=QuotaReservationResponse,
)
def reserve_saas_quota(
    deployment_id: str, body: QuotaReservationRequest, request: Request
) -> dict:
    workload = _reconciler_identity(request)
    try:
        row = _store().reserve_quota(
            deployment_id,
            workload,
            body.invocation_id,
            body.request_digest,
            body.dimension,
            body.amount,
        )
        return _serializable(row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post(
    "/internal/v1/saas/deployments/{deployment_id}/quota/reservations/{reservation_id}/commit",
    response_model=QuotaReservationResponse,
)
def commit_saas_quota(
    deployment_id: str,
    reservation_id: str,
    body: QuotaCommitRequest,
    request: Request,
) -> dict:
    workload = _reconciler_identity(request)
    try:
        row = _store().commit_quota(
            deployment_id,
            workload,
            reservation_id,
            body.request_digest,
            body.actual_amount,
        )
        return _serializable(row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/byoc/enrollments", response_model=BYOCEnrollmentResponse)
def create_byoc_enrollment(
    body: BYOCEnrollmentRequest,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        enrollment_id, token, token_digest = enrollment_material(body, actor)
        row = _store().create_byoc_enrollment(body, actor, enrollment_id, token_digest)
        response = _serializable(row)
        response["enrollment_token"] = token
        return response
    except (ManagementError, ManagementUnavailable, RuntimeError) as exc:
        raise _error(exc) from exc


@app.post("/internal/v1/byoc/enroll", response_model=BYOCEnrollmentCompleteResponse)
def enroll_byoc_connector(body: BYOCEnrollRequest, request: Request) -> dict:
    workload = _reconciler_identity(request)
    try:
        certificate = issue_connector_certificate(
            body.certificate_signing_request, workload
        )
        response = _serializable(
            _store().enroll_byoc_connector(
                str(body.enrollment_id),
                body.enrollment_token,
                body.account_id,
                body.local_policy_digest,
                body.connector_public_key,
                body.proof_signature,
                workload,
            )
        )
        response.update(certificate)
        return response
    except (ManagementError, ManagementUnavailable, RuntimeError) as exc:
        raise _error(exc) from exc


@app.post(
    "/internal/v1/byoc/deployments/{deployment_id}/certificate/rotate",
    response_model=BYOCCertificateResponse,
)
def rotate_byoc_connector_certificate(
    deployment_id: str, body: BYOCCertificateRotationRequest, request: Request
) -> dict:
    workload = _reconciler_identity(request)
    try:
        _store().authorize_byoc_certificate_rotation(deployment_id, workload)
        return issue_connector_certificate(body.certificate_signing_request, workload)
    except (ManagementError, ManagementUnavailable, RuntimeError) as exc:
        raise _error(exc) from exc


@app.post(
    "/internal/v1/byoc/deployments/{deployment_id}/health",
    response_model=BYOCHealthReceipt,
)
def submit_byoc_health(
    deployment_id: str, body: BYOCHealthEvent, request: Request
) -> dict:
    workload = _reconciler_identity(request)
    try:
        return _store().record_byoc_health(deployment_id, workload, body)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post(
    "/v1/tenants/{tenant_id}/deployments/{deployment_id}/byoc/revoke",
    response_model=BYOCConnectorResponse,
)
def revoke_byoc_management(
    tenant_id: str,
    deployment_id: str,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        return _serializable(
            _store().revoke_byoc_management(tenant_id, deployment_id, actor)
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.put("/v1/enterprise/identity-providers/{provider_id}")
def configure_identity_provider(
    provider_id: str,
    body: IdentityProviderRequest,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    if provider_id != body.provider_id:
        raise HTTPException(status_code=409, detail="identity provider path mismatch")
    try:
        return _serializable(_identity_store().configure_provider(body, actor))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/enterprise/identity-providers/{provider_id}/scim-tokens", status_code=201)
def create_scim_token(
    provider_id: str,
    body: SCIMTokenRequest,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        row, token = _identity_store().issue_scim_token(provider_id, body.expires_at, actor)
        return {**_serializable(row), "token": token}
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/sso/saml/{provider_id}/login", response_model=SAMLLoginResponse)
def begin_saml_login(provider_id: str) -> dict:
    try:
        return _serializable(_identity_store().begin_saml_login(provider_id))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/sso/saml/{provider_id}/acs", response_model=FederatedSessionResponse)
def consume_saml_assertion(provider_id: str, body: SAMLAssertionRequest) -> dict:
    try:
        token, expiry = _identity_store().consume_saml_assertion(
            provider_id, body.saml_response, body.relay_state
        )
        return {"access_token": token, "token_type": "Bearer", "expires_at": expiry}
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


def _scim_provider(authorization: str | None) -> tuple[EnterpriseIdentityStore, str]:
    store = _identity_store()
    try:
        return store, store.scim_provider(authorization)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/scim/v2/ServiceProviderConfig")
def scim_service_provider_config() -> JSONResponse:
    return JSONResponse(
        media_type="application/scim+json",
        content={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": False},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 1000},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": True},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "SCIM bearer token",
                    "description": "Provider-bound, expiring bearer token",
                    "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                    "primary": True,
                }
            ],
        },
    )


@app.post("/scim/v2/Users", status_code=201)
def create_scim_user(
    body: dict,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.upsert_scim_user(provider_id, body)
        return JSONResponse(media_type="application/scim+json", status_code=201, content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.put("/scim/v2/Users/{external_id}")
def replace_scim_user(
    external_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.upsert_scim_user(provider_id, body, external_id)
        return JSONResponse(media_type="application/scim+json", content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/scim/v2/Users/{external_id}")
def get_scim_user(
    external_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.get_scim_user(provider_id, external_id)
        if row is None:
            raise HTTPException(status_code=404, detail="SCIM user not found")
        return JSONResponse(media_type="application/scim+json", content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/scim/v2/Users")
def list_scim_users(
    filter_value: str | None = Query(default=None, alias="filter"),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        rows = store.list_scim_users(provider_id, filter_value)
        return JSONResponse(
            media_type="application/scim+json",
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": len(rows),
                "startIndex": 1,
                "itemsPerPage": len(rows),
                "Resources": rows,
            },
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.delete("/scim/v2/Users/{external_id}", status_code=204)
def delete_scim_user(
    external_id: str,
    authorization: str | None = Header(default=None),
) -> None:
    store, provider_id = _scim_provider(authorization)
    try:
        store.deactivate_scim_user(provider_id, external_id)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/scim/v2/Groups", status_code=201)
def create_scim_group(
    body: dict,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.upsert_scim_group(provider_id, body)
        return JSONResponse(media_type="application/scim+json", status_code=201, content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.put("/scim/v2/Groups/{external_id}")
def replace_scim_group(
    external_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.upsert_scim_group(provider_id, body, external_id)
        return JSONResponse(media_type="application/scim+json", content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/scim/v2/Groups/{external_id}")
def get_scim_group(
    external_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    store, provider_id = _scim_provider(authorization)
    try:
        row = store.get_scim_group(provider_id, external_id)
        if row is None:
            raise HTTPException(status_code=404, detail="SCIM group not found")
        return JSONResponse(media_type="application/scim+json", content=row)
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/operator-access/requests", status_code=201)
def request_operator_access(
    body: OperatorAccessRequest,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        return _serializable(_operator_access_store().create_request(body, actor))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/operator-access/requests/{request_id}/customer-approve")
def customer_approve_operator_access(
    request_id: str,
    body: OperatorAccessApproval,
    actor: CustomerIdentity = Depends(current_customer),
) -> dict:
    try:
        return _serializable(
            _operator_access_store().customer_approve(request_id, body.request_digest, actor)
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/operator-access/requests/{request_id}/provider-approve")
def provider_approve_operator_access(
    request_id: str,
    body: OperatorAccessApproval,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        return _serializable(
            _operator_access_store().provider_approve(request_id, body.request_digest, actor)
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post(
    "/v1/operator-access/requests/{request_id}/activate",
    response_model=OperatorAccessSessionResponse,
)
def activate_operator_access(
    request_id: str,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        session, token = _operator_access_store().activate(request_id, actor)
        return {
            "session_id": session["session_id"],
            "request_id": session["request_id"],
            "tenant_id": session["tenant_id"],
            "deployment_id": session["deployment_id"],
            "expires_at": session["expires_at"],
            "session_token": token,
        }
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post(
    "/internal/v1/operator-access/sessions/{session_id}/authorize",
    response_model=OperatorAccessDecision,
)
def authorize_operator_access(
    session_id: str,
    body: OperatorAccessAuthorization,
    request: Request,
    session_token: str = Header(alias="X-Autobot-Support-Session"),
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    workload = _reconciler_identity(request)
    try:
        decision = _operator_access_store().authorize(
            session_id, session_token, body.action, body.resource, actor, workload
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
    if not decision["allowed"]:
        raise HTTPException(
            status_code=403,
            detail={"code": decision["reason_code"], "message": "operator access denied"},
        )
    return decision


@app.post("/v1/operator-access/requests/{request_id}/revoke")
def operator_revoke_access(
    request_id: str,
    actor: OperatorIdentity = Depends(current_operator),
) -> dict:
    try:
        return _serializable(_operator_access_store().revoke_by_operator(request_id, actor))
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.post("/v1/tenants/{tenant_id}/operator-access/requests/{request_id}/revoke")
def customer_revoke_access(
    tenant_id: str,
    request_id: str,
    actor: CustomerIdentity = Depends(current_customer),
) -> dict:
    try:
        return _serializable(
            _operator_access_store().revoke_by_customer(request_id, tenant_id, actor)
        )
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc


@app.get("/v1/tenants/{tenant_id}/operator-access/audit")
def customer_operator_access_audit(
    tenant_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    actor: CustomerIdentity = Depends(current_customer),
) -> list[dict]:
    try:
        return [
            _serializable(row)
            for row in _operator_access_store().list_customer_audit(tenant_id, actor, limit)
        ]
    except (ManagementError, ManagementUnavailable) as exc:
        raise _error(exc) from exc
