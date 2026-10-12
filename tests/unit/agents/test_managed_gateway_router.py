from __future__ import annotations

from datetime import datetime, timedelta, timezone
from starlette.requests import Request
from fastapi import HTTPException
import pytest

from core.agents import managed_gateway_router
from core.agents.managed_execution import managed_digest
from core.agents.managed_gateway_router import (
    ManagedGrantPayload,
    ManagedGrantRequest,
    ManagedPendingApproval,
    ManagedStatusRequest,
    _record_denial,
    _require_spiffe_workload,
    issue_managed_grant,
    update_managed_execution_status,
)
from core.agents.managed_execution import (
    ExecutionIdentity,
    ManagedAuthority,
    ManagedSecurityError,
    ToolGrant,
)


WORKLOAD = "spiffe://tenant-a.autobot.example/ns/tenant-a/sa/vigil-worker"


def _request(**scope_values: object) -> Request:
    return Request({"type": "http", "method": "POST", "path": "/v1/claim", "headers": [], **scope_values})


def test_caller_supplied_certificate_fingerprint_is_not_workload_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    monkeypatch.setenv("VIGIL_IDENTITY_PROXY_TOKEN", "proxy-secret")

    with pytest.raises(HTTPException) as denied:
        _require_spiffe_workload(_request(), None, None)

    assert denied.value.status_code == 401


def test_identity_proxy_must_bind_token_and_expected_spiffe_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    monkeypatch.setenv("VIGIL_IDENTITY_PROXY_TOKEN", "proxy-secret")

    assert _require_spiffe_workload(_request(), WORKLOAD, "proxy-secret") == WORKLOAD
    with pytest.raises(HTTPException) as denied:
        _require_spiffe_workload(_request(), "spiffe://tenant-b/worker", "proxy-secret")
    assert denied.value.status_code == 403


def test_in_process_verified_spiffe_scope_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    monkeypatch.delenv("VIGIL_IDENTITY_PROXY_TOKEN", raising=False)

    assert _require_spiffe_workload(_request(**{"vigil.verified_spiffe_id": WORKLOAD}), None, None) == WORKLOAD


def test_gateway_issues_a_signed_exact_bound_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    monkeypatch.setenv("VIGIL_MANAGED_BUILTIN_TOOLS", "get_finding")
    monkeypatch.delenv("VIGIL_MANAGED_APPROVAL_ACTIONS", raising=False)
    now = datetime.now(timezone.utc)
    signer = ManagedAuthority()

    class Store:
        def authorization_context(self, execution_id, workload_id, claim_token):
            return {
                "execution_id": execution_id, "tenant_id": "tenant-a",
                "deployment_id": "deployment-a",
                "deployment_incarnation": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "workflow_id": "triage-v1",
                "workflow_digest": "workflow-digest", "program_id": "triage-dspy-v1",
                "program_digest": "program-digest", "capabilities": ["get_finding"],
                "policy_version": "policy-1", "revocation_epoch": 0,
                "issued_at": now, "expires_at": now + timedelta(minutes=5),
                "jti": claim_token,
            }

    class Authority:
        @staticmethod
        def verify_execution_attestation(identity, attestation):
            assert attestation == "signed-execution"

        @staticmethod
        def sign_tool_grant(grant):
            return signer.sign_tool_grant(grant)

    monkeypatch.setattr(managed_gateway_router, "ManagedRunStore", Store)
    monkeypatch.setattr(managed_gateway_router, "authority", Authority())
    body = ManagedGrantRequest(
        execution_id="00000000-0000-4000-8000-000000000001",
        tenant_id="tenant-a", deployment_id="deployment-a",
        deployment_incarnation="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        claim_token="claim-1", attestation="signed-execution",
        tool="get_finding", args={"finding_id": "finding-a"},
        max_rows=7, timeout_ms=900,
    )

    result = issue_managed_grant(
        body, _request(**{"vigil.verified_spiffe_id": WORKLOAD}), registry=object()
    )

    payload = ManagedGrantPayload(**result)
    grant = ToolGrant(**payload.model_dump())
    signer.verify_tool_grant(grant)
    assert grant.resource == "finding-a"
    assert grant.max_rows == 7
    assert grant.timeout_ms == 900


def test_denial_audit_uses_resolved_identity_and_ignores_unresolved_requests() -> None:
    now = datetime.now(timezone.utc)
    identity = ExecutionIdentity(
        execution_id="00000000-0000-4000-8000-000000000001",
        tenant_id="tenant-a", deployment_id="deployment-a",
        deployment_incarnation="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        worker_key_id=WORKLOAD, workflow_id="triage-v1",
        workflow_digest="workflow-digest", program_id="triage-dspy-v1",
        program_digest="program-digest", capabilities=("get_finding",),
        policy_version="policy-1", revocation_epoch=0, issued_at=now,
        expires_at=now + timedelta(minutes=5), jti="claim-1",
    )
    captured: list[dict[str, object]] = []

    class Store:
        def record_authorization_denial(self, **kwargs):
            captured.append(kwargs)
            return True

    store = Store()
    error = ManagedSecurityError("invalid managed envelope signature")
    _record_denial(
        store, None, action="get_finding", resource="foreign",
        arguments={"finding_id": "foreign"}, error=error,
    )
    assert captured == []

    _record_denial(
        store, identity, action="get_finding", resource="finding-a",
        arguments={"finding_id": "finding-a"}, error=error,
    )
    assert captured[0]["tenant_id"] == "tenant-a"
    assert captured[0]["execution_id"] == identity.execution_id
    assert captured[0]["reason_code"] == "grant_invalid"


@pytest.mark.asyncio
async def test_waiting_status_binds_the_worker_checkpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    now = datetime.now(timezone.utc)
    captured: dict[str, object] = {}

    class Store:
        def authorization_context(self, execution_id, workload_id, claim_token):
            return {
                "execution_id": execution_id,
                "tenant_id": "tenant-a",
                "deployment_id": "deployment-a",
                "deployment_incarnation": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "workflow_id": "triage-v1",
                "workflow_digest": "workflow-digest",
                "program_id": "triage-dspy-v1",
                "program_digest": "program-digest",
                "capabilities": ["findings.read"],
                "policy_version": "policy-1",
                "revocation_epoch": 0,
                "issued_at": now,
                "expires_at": now + timedelta(minutes=5),
                "jti": claim_token,
            }

        def update_execution_status(self, **kwargs):
            captured.update(kwargs)
            return True

    class Authority:
        @staticmethod
        def verify_execution_attestation(identity, attestation):
            assert attestation == "signed"

    monkeypatch.setattr(managed_gateway_router, "ManagedRunStore", Store)
    monkeypatch.setattr(managed_gateway_router, "authority", Authority())
    body = ManagedStatusRequest(
        execution_id="00000000-0000-4000-8000-000000000001",
        claim_token="claim-1",
        attestation="signed",
        status="waiting_approval",
        pending=ManagedPendingApproval(
            checkpoint_id="checkpoint-1",
            tool="findings.read",
            args='{"finding_id":"finding-a"}',
        ),
    )

    result = update_managed_execution_status(
        body,
        _request(**{"vigil.verified_spiffe_id": WORKLOAD}),
        registry=object(),
    )

    assert result["status"] == "waiting_approval"
    assert captured["pending_approval"] == {
        "checkpoint_id": "checkpoint-1",
        "action": "findings.read",
        "resource": "finding-a",
        "argument_digest": managed_digest({"finding_id": "finding-a"}),
    }


@pytest.mark.asyncio
async def test_waiting_status_without_exact_action_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_EXECUTION_PROFILE", "managed")
    monkeypatch.setenv("VIGIL_WORKER_SPIFFE_ID", WORKLOAD)
    now = datetime.now(timezone.utc)

    class Store:
        def authorization_context(self, execution_id, workload_id, claim_token):
            return {
                "execution_id": execution_id, "tenant_id": "tenant-a",
                "deployment_id": "deployment-a",
                "deployment_incarnation": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "workflow_id": "triage-v1",
                "workflow_digest": "w", "program_id": "triage-dspy-v1",
                "program_digest": "p", "capabilities": ["findings.read"],
                "policy_version": "policy-1", "revocation_epoch": 0,
                "issued_at": now, "expires_at": now + timedelta(minutes=5),
                "jti": claim_token,
            }

    class Authority:
        @staticmethod
        def verify_execution_attestation(identity, attestation):
            return None

    monkeypatch.setattr(managed_gateway_router, "ManagedRunStore", Store)
    monkeypatch.setattr(managed_gateway_router, "authority", Authority())
    body = ManagedStatusRequest(
        execution_id="00000000-0000-4000-8000-000000000001",
        claim_token="claim-1", attestation="signed", status="waiting_approval",
    )

    with pytest.raises(HTTPException) as denied:
        update_managed_execution_status(
            body,
            _request(**{"vigil.verified_spiffe_id": WORKLOAD}),
            registry=object(),
        )
    assert denied.value.status_code == 403
