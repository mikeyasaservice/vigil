"""Negative tests for the Phase 2 admission and gateway boundary."""

from datetime import timedelta

import pytest

from core.agents.managed_execution import (
    AuthorizationUnavailable,
    Invocation,
    ManagedAuthority,
    ManagedSecurityError,
    TenantContext,
)


def context(tenant: str = "tenant-a") -> TenantContext:
    return TenantContext(
        tenant_id=tenant,
        deployment_id=f"deployment-{tenant}",
        subject_id="user-a",
        issuer="https://issuer.test",
        roles=("analyst",),
        membership_version=1,
        policy_version="policy-1",
        request_id="request-1",
    )


def test_signed_admission_rejects_tampering_before_claim() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(),
        admission_id="admission-a",
        workflow_id="triage-v1",
        workflow_digest="workflow-digest",
        program_id="triage-dspy-v1",
        program_digest="program-digest",
        request={"finding_ids": ["finding-a"]},
    )
    tampered = envelope.__class__(
        admission=envelope.admission,
        execution_id=envelope.execution_id,
        reason="resume",
        references=envelope.references,
        signature=envelope.signature,
    )
    with pytest.raises(ManagedSecurityError):
        authority.claim(tampered, worker_key_id="worker-a", capabilities=("findings.read",))


def test_foreign_tenant_and_wrong_worker_cannot_use_grant() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="admission-a", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}
    )
    identity = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    grant = authority.grant(identity, grant_id="grant-a", action="findings.read", resource="finding-a", arguments={"id": "finding-a"}, workload_key_id="worker-a")
    invocation = Invocation("invocation-a", identity.execution_id, "tenant-a", "findings.read", "finding-a", {"id": "finding-a"}, grant)
    authority.authorize(invocation)
    foreign = Invocation("invocation-b", identity.execution_id, "tenant-b", "findings.read", "finding-a", {"id": "finding-a"}, grant)
    with pytest.raises(ManagedSecurityError):
        authority.authorize(foreign)
    with pytest.raises(ManagedSecurityError):
        authority.grant(identity, grant_id="grant-b", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-b")


def test_revocation_and_missing_budget_fail_closed() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="admission-a", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}
    )
    identity = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    grant = authority.grant(identity, grant_id="grant-a", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    invocation = Invocation("invocation-a", identity.execution_id, "tenant-a", "findings.read", "finding-a", {}, grant)
    authority.revoke("tenant-a")
    with pytest.raises(ManagedSecurityError):
        authority.authorize(invocation)
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="admission-b", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}
    )
    identity = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    grant = authority.grant(identity, grant_id="grant-b", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    authority.budgets.pop(identity.execution_id)
    with pytest.raises(AuthorizationUnavailable):
        authority.authorize(Invocation("invocation-b", identity.execution_id, "tenant-a", "findings.read", "finding-a", {}, grant))


def test_invocation_id_cannot_change_arguments() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="admission-a", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}
    )
    identity = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    grant = authority.grant(identity, grant_id="grant-a", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    invocation = Invocation("same-id", identity.execution_id, "tenant-a", "findings.read", "finding-a", {}, grant)
    authority.record_invocation(invocation, {"ok": True})
    changed = Invocation("same-id", identity.execution_id, "tenant-a", "findings.read", "finding-a", {"id": "other"}, grant)
    with pytest.raises(ManagedSecurityError):
        authority.record_invocation(changed, {"ok": True})
