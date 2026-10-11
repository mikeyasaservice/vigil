"""Pinned triage program.

The DSPy implementation is loaded only inside the reasoner process. The
harness receives a typed proposal and remains responsible for authorization.
The deterministic branch is used by CI and never claims model-quality results.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from services.reasoner.contracts import TriageInput, TriageOutput

PROGRAM_ID = "triage-dspy-v1"
PROGRAM_VERSION = "1.0.0"


def _deterministic(value: TriageInput) -> TriageOutput:
    refs = tuple(str(item.get("evidence_id")) for item in value.evidence if item.get("evidence_id"))
    return TriageOutput(
        hypotheses=(f"findings {', '.join(value.finding_ids)} require analyst review",),
        evidence_refs=refs[:10],
        confidence=0.5 if refs else 0.1,
        limitations=("deterministic fixture; no model-quality claim",),
        proposed_actions=("propose:review",),
        input_tokens=0,
        output_tokens=0,
    ).validate(set(refs))


def evaluate(value: TriageInput) -> TriageOutput:
    if os.getenv("VIGIL_REASONER_MODE", "deterministic") == "deterministic":
        return _deterministic(value)
    try:
        import dspy
    except ImportError as exc:
        raise RuntimeError("DSPy is required for live reasoner evaluation") from exc

    class TriageSignature(dspy.Signature):
        """Ground triage hypotheses in the supplied evidence."""

        finding_ids = dspy.InputField()
        evidence = dspy.InputField()
        hypotheses = dspy.OutputField()
        evidence_refs = dspy.OutputField()
        confidence = dspy.OutputField()
        limitations = dspy.OutputField()
        proposed_actions = dspy.OutputField(desc="proposal strings only, never executable commands")

    prediction = dspy.Predict(TriageSignature)(finding_ids=value.finding_ids, evidence=value.evidence)
    output = TriageOutput(
        hypotheses=tuple(prediction.hypotheses if isinstance(prediction.hypotheses, list) else [str(prediction.hypotheses)]),
        evidence_refs=tuple(prediction.evidence_refs if isinstance(prediction.evidence_refs, list) else [str(prediction.evidence_refs)]),
        confidence=float(prediction.confidence),
        limitations=tuple(prediction.limitations if isinstance(prediction.limitations, list) else [str(prediction.limitations)]),
        proposed_actions=tuple(prediction.proposed_actions if isinstance(prediction.proposed_actions, list) else [str(prediction.proposed_actions)]),
    )
    return output.validate({str(item.get("evidence_id")) for item in value.evidence if item.get("evidence_id")})
