"""Typed boundary between DSPy reasoning and the trusted execution harness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Tuple


@dataclass(frozen=True)
class TriageInput:
    execution_id: str
    finding_ids: Tuple[str, ...]
    evidence: Tuple[Mapping[str, Any], ...]
    budget_tokens: int


@dataclass(frozen=True)
class TriageOutput:
    hypotheses: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]
    confidence: float
    limitations: Tuple[str, ...]
    proposed_actions: Tuple[str, ...]
    input_tokens: int = 0
    output_tokens: int = 0

    def validate(self, allowed_evidence: set[str]) -> "TriageOutput":
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if any(ref not in allowed_evidence for ref in self.evidence_refs):
            raise ValueError("reasoner returned an evidence reference outside the input")
        if any(not action.startswith("propose:") for action in self.proposed_actions):
            raise ValueError("reasoner actions must be proposals, never executable commands")
        if self.input_tokens + self.output_tokens < 0:
            raise ValueError("token usage cannot be negative")
        return self
