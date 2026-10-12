"""The tenant-local reasoner verifies the exact managed execution identity."""

from core.agents.managed_execution import ManagedAuthority, TenantContext
from services.reasoner.app import EvaluateRequest, _verify_execution
from services.reasoner.programs.triage_v1 import PROGRAM_ID, artifact_digest


def test_reasoner_attestation_includes_deployment_incarnation(monkeypatch):
    authority = ManagedAuthority()
    context = TenantContext(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        deployment_incarnation="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        subject_id="analyst-a",
        issuer="https://issuer.example",
        roles=("analyst",),
        membership_version=1,
        policy_version="policy-1",
        request_id="request-1",
    )
    envelope = authority.admit(
        context,
        admission_id="admission-a",
        workflow_id="triage-v1",
        workflow_digest="workflow-digest",
        program_id=PROGRAM_ID,
        program_digest=artifact_digest(),
        request={"finding_ids": ["finding-a"]},
    )
    identity = authority.claim(
        envelope,
        worker_key_id="spiffe://autobot.internal/ns/tenant-a/sa/worker",
        capabilities=("findings.read",),
    )
    raw = {
        **identity.__dict__,
        "workload_spiffe_id": identity.worker_key_id,
        "issued_at": identity.issued_at.isoformat(),
        "expires_at": identity.expires_at.isoformat(),
        "attestation": authority.sign_execution_attestation(identity),
    }
    monkeypatch.setenv(
        "VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY", authority.signer.public_key_b64
    )

    verified = _verify_execution(
        EvaluateRequest(
            program_id=PROGRAM_ID,
            program_digest=artifact_digest(),
            execution_identity=raw,
            input={"execution_id": identity.execution_id},
        )
    )

    assert verified.deployment_incarnation == context.deployment_incarnation
