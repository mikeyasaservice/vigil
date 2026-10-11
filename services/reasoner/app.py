"""Tenant-local HTTP boundary for the approved triage program.

The reasoner proposes typed results only. It has no tool registry and no
credentials; the TypeScript harness and capability gateway remain responsible
for every side effect.
"""

from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from services.reasoner.contracts import TriageInput
from services.reasoner.programs.triage_v1 import PROGRAM_ID, PROGRAM_VERSION, artifact_digest, evaluate


class EvaluateRequest(BaseModel):
    program_id: str = Field(min_length=1, max_length=100)
    program_digest: str = Field(min_length=1, max_length=200)
    input: dict[str, Any]


app = FastAPI(title="Vigil tenant-local reasoner", version=PROGRAM_VERSION)


def _authorize(authorization: str | None) -> None:
    expected = os.getenv("VIGIL_REASONER_INTERNAL_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="reasoner trust material is unavailable")
    presented = (authorization or "").removeprefix("Bearer ")
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="reasoner authorization failed")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "program_id": PROGRAM_ID, "version": PROGRAM_VERSION, "artifact_digest": artifact_digest()}


@app.post("/v1/evaluate")
def evaluate_reasoner(
    request: EvaluateRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(authorization)
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
