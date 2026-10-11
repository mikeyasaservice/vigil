"""Tenant-local HTTP boundary for the approved triage program.

The reasoner proposes typed results only. It has no tool registry and no
credentials; the TypeScript harness and capability gateway remain responsible
for every side effect.
"""

from __future__ import annotations

import hmac
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.agents.managed_execution import Ed25519Verifier, ExecutionIdentity, ManagedAuthority, ManagedSecurityError
from services.reasoner.contracts import TriageInput
from services.reasoner.programs.triage_v1 import PROGRAM_ID, PROGRAM_VERSION, artifact_digest, evaluate


class EvaluateRequest(BaseModel):
    program_id: str = Field(min_length=1, max_length=100)
    program_digest: str = Field(min_length=1, max_length=200)
    execution_identity: dict[str, Any]
    input: dict[str, Any]


app = FastAPI(title="Vigil tenant-local reasoner", version=PROGRAM_VERSION)


def _authorize(authorization: str | None) -> None:
    expected = os.getenv("VIGIL_REASONER_INTERNAL_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="reasoner trust material is unavailable")
    presented = (authorization or "").removeprefix("Bearer ")
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="reasoner authorization failed")


def _verify_execution(request: EvaluateRequest) -> ExecutionIdentity:
    public_raw = os.getenv("VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY", "")
    if not public_raw:
        raise HTTPException(status_code=503, detail="reasoner authority trust is unavailable")
    try:
        raw = request.execution_identity
        padded = public_raw + "=" * (-len(public_raw) % 4)
        verifier = Ed25519Verifier(
            Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(padded)),
            "managed-authority",
        )
        identity = ExecutionIdentity(
            execution_id=str(raw["execution_id"]), tenant_id=str(raw["tenant_id"]),
            deployment_id=str(raw["deployment_id"]),
            worker_key_id=str(raw.get("workload_spiffe_id") or raw["worker_key_id"]),
            workflow_id=str(raw["workflow_id"]), workflow_digest=str(raw["workflow_digest"]),
            program_id=str(raw["program_id"]), program_digest=str(raw["program_digest"]),
            capabilities=tuple(str(value) for value in raw["capabilities"]),
            policy_version=str(raw["policy_version"]), revocation_epoch=int(raw["revocation_epoch"]),
            issued_at=datetime.fromisoformat(str(raw.get("issued_at") or raw["expires_at"])),
            expires_at=datetime.fromisoformat(str(raw["expires_at"])), jti=str(raw["jti"]),
        )
        ManagedAuthority(verifier=verifier).verify_execution_attestation(identity, str(raw["attestation"]))
    except (KeyError, TypeError, ValueError, ManagedSecurityError) as exc:
        raise HTTPException(status_code=403, detail="reasoner execution attestation is invalid") from exc
    if identity.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="reasoner execution attestation expired")
    if identity.execution_id != str(request.input.get("execution_id", "")):
        raise HTTPException(status_code=403, detail="reasoner execution binding is invalid")
    if identity.program_id != request.program_id or identity.program_digest != request.program_digest:
        raise HTTPException(status_code=403, detail="reasoner program binding is invalid")
    return identity


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "program_id": PROGRAM_ID, "version": PROGRAM_VERSION, "artifact_digest": artifact_digest()}


@app.post("/v1/evaluate")
def evaluate_reasoner(
    request: EvaluateRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(authorization)
    _verify_execution(request)
    if request.program_id != PROGRAM_ID:
        raise HTTPException(status_code=403, detail="program is not approved")
    manifest = json.loads((Path(__file__).resolve().parent / "programs" / "triage-v1.manifest.json").read_text())
    if not hmac.compare_digest(request.program_digest, str(manifest.get("artifact_digest", ""))) or not hmac.compare_digest(str(manifest.get("artifact_digest", "")), artifact_digest()):
        raise HTTPException(status_code=503, detail="reasoner artifact is not approved")
    try:
        value = TriageInput(
            execution_id=str(request.input["execution_id"]),
            finding_ids=tuple(str(item) for item in request.input["finding_ids"]),
            evidence=tuple(request.input["evidence"]),
            budget_tokens=int(request.input["budget_tokens"]),
        )
        result = evaluate(value)
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail="reasoner input or output was rejected") from exc
    return {
        "program_id": PROGRAM_ID,
        "program_version": PROGRAM_VERSION,
        "hypotheses": list(result.hypotheses),
        "evidence_refs": list(result.evidence_refs),
        "confidence": result.confidence,
        "limitations": list(result.limitations),
        "proposed_actions": list(result.proposed_actions),
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
    }
