"""Negative tests for the Phase 2 admission and gateway boundary."""

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import json
from pathlib import Path

import pytest

from core.agents.managed_execution import (
    AuthorizationUnavailable,
    Invocation,
    ManagedAuthority,
    ManagedSecurityError,
    QueueEnvelope,
    TenantContext,
    managed_digest,
)


def test_managed_digest_matches_cross_language_rfc8785_fixture() -> None:
    fixture_path = Path(__file__).parents[3] / "contracts" / "fixtures" / "managed-canonicalization.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert managed_digest(fixture["input"]) == fixture["sha256"]


def test_resume_renews_expired_admission_without_changing_pinned_work() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="resume-expired", workflow_id="triage-v1",
        workflow_digest="workflow-digest", program_id="triage-dspy-v1",
        program_digest="program-digest", request={"finding_ids": ["finding-a"]},
    )
    expired_admission = replace(
        envelope.admission,
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    expired = replace(envelope, admission=expired_admission, signature="")
    expired = replace(expired, signature=authority.signer.sign(expired.signed_payload))
    authority.admissions[expired_admission.admission_id] = expired_admission

    resumed = authority.reissue(expired, reason="resume")

    assert resumed.reason == "resume"
    assert resumed.execution_id == envelope.execution_id
    assert resumed.references == envelope.references
    assert resumed.admission.request_digest == envelope.admission.request_digest
    assert resumed.admission.program_digest == envelope.admission.program_digest
    assert resumed.admission.expires_at > datetime.now(timezone.utc)


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


def test_signed_envelope_transport_round_trip_remains_claimable() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="admission-round-trip", workflow_id="triage-v1",
        workflow_digest="workflow-digest", program_id="triage-dspy-v1",
        program_digest="program-digest", request={"finding_ids": ["finding-a"]},
    )

    serialized = envelope.as_dict()
    assert serialized["schema_version"] == 3
    transported = QueueEnvelope.from_dict(serialized)
    identity = authority.claim(
        transported, worker_key_id="worker-a", capabilities=("findings.read",)
    )

    assert identity.execution_id == envelope.execution_id
    assert transported.signature == envelope.signature


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


def test_tool_grant_signature_binds_arguments_bounds_and_claim() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="signed-grant", workflow_id="triage-v1",
        workflow_digest="w", program_id="p", program_digest="pd", request={},
    )
    identity = authority.claim(
        envelope, worker_key_id="worker-a", capabilities=("findings.read",)
    )
    grant = authority.grant(
        identity, grant_id="grant-signed", action="findings.read",
        resource="finding-a", arguments={"id": "finding-a"},
        workload_key_id="worker-a", max_rows=10, timeout_ms=500,
    )

    assert grant.signature
    authority.verify_tool_grant(grant)
    for changed in (
        replace(grant, argument_digest="0" * 64),
        replace(grant, max_rows=11),
        replace(grant, claim_jti="other-claim"),
    ):
        with pytest.raises(ManagedSecurityError):
            authority.verify_tool_grant(changed)


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


def test_grant_cannot_cross_execution_or_increase_budget() -> None:
    authority = ManagedAuthority()
    first = authority.claim(
        authority.admit(context(), admission_id="a", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}),
        worker_key_id="worker-a",
        capabilities=("findings.read",),
    )
    second = authority.claim(
        authority.admit(context(), admission_id="b", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}),
        worker_key_id="worker-b",
        capabilities=("findings.read",),
    )
    grant = authority.grant(first, grant_id="grant-a", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    with pytest.raises(ManagedSecurityError):
        authority.authorize(Invocation("foreign", second.execution_id, second.tenant_id, "findings.read", "finding-a", {}, grant))
    before = authority.budgets[first.execution_id]
    with pytest.raises(ManagedSecurityError):
        Invocation("negative", first.execution_id, first.tenant_id, "findings.read", "finding-a", {}, grant, budget_units=-1)
    assert authority.budgets[first.execution_id] == before


def test_repeated_authorization_reserves_budget_once() -> None:
    authority = ManagedAuthority()
    identity = authority.claim(
        authority.admit(context(), admission_id="once", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={}),
        worker_key_id="worker-a",
        capabilities=("findings.read",),
    )
    grant = authority.grant(identity, grant_id="grant-once", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    invocation = Invocation("once", identity.execution_id, identity.tenant_id, "findings.read", "finding-a", {}, grant)
    authority.authorize(invocation)
    remaining = authority.budgets[identity.execution_id]
    authority.authorize(invocation)
    assert authority.budgets[identity.execution_id] == remaining


def test_worker_takeover_fences_old_grants() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(context(), admission_id="takeover", workflow_id="triage-v1", workflow_digest="w", program_id="p", program_digest="pd", request={})
    first = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    grant = authority.grant(first, grant_id="takeover-grant", action="findings.read", resource="finding-a", arguments={}, workload_key_id="worker-a")
    second = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    assert first.jti != second.jti
    with pytest.raises(ManagedSecurityError):
        authority.authorize(Invocation("takeover", second.execution_id, second.tenant_id, "findings.read", "finding-a", {}, grant))


def test_execution_attestation_is_bound_to_claim() -> None:
    authority = ManagedAuthority()
    envelope = authority.admit(
        context(), admission_id="attestation", workflow_id="triage-v1", workflow_digest="w",
        program_id="p", program_digest="pd", request={},
    )
    identity = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    attestation = authority.sign_execution_attestation(identity)
    authority.verify_execution_attestation(identity, attestation)
    replacement = authority.claim(envelope, worker_key_id="worker-a", capabilities=("findings.read",))
    with pytest.raises(ManagedSecurityError):
        authority.verify_execution_attestation(replacement, attestation)
