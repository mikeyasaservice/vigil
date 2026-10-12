"""Tenant-local DSPy dataset evaluation and candidate lifecycle primitives.

The module deliberately separates sensitive local records from the aggregate
receipt that can be sent to the management plane.  It never executes tools and
never embeds dataset examples or local trace references in an export receipt.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from services.reasoner.contracts import TriageInput, TriageOutput

SCHEMA_VERSION = "autobot.dspy.dataset/v1"
RECEIPT_VERSION = "autobot.dspy.evaluation-receipt/v1"
SPLITS = ("train", "development", "holdout", "safety")


class LifecycleError(ValueError):
    """A lifecycle artifact failed a fail-closed validation rule."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class EvaluationThresholds:
    minimum_pass_rate: float
    minimum_grounding_rate: float
    minimum_action_safety_rate: float
    maximum_failure_rate: float

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if (
                not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise LifecycleError(f"{name} must be between zero and one")


@dataclass(frozen=True)
class EvaluationResult:
    metrics: Mapping[str, int | float]
    failures: tuple[Mapping[str, str], ...]
    passed: bool
    used_tokens: int


def _require_string(value: Any, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise LifecycleError(f"{field} is invalid")
    return value


def validate_dataset(
    raw: Mapping[str, Any], *, tenant_id: str, deployment_id: str
) -> dict[str, Any]:
    """Validate ownership, four-way splits, evidence references and uniqueness."""
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("dataset schema version is unsupported")
    try:
        uuid.UUID(str(raw["dataset_id"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise LifecycleError("dataset ID must be a UUID") from exc
    if raw.get("tenant_id") != tenant_id or raw.get("deployment_id") != deployment_id:
        raise LifecycleError("dataset does not match the authenticated deployment")
    _require_string(raw.get("use_purpose"), "use purpose")
    splits = raw.get("splits")
    if not isinstance(splits, Mapping) or set(splits) != set(SPLITS):
        raise LifecycleError(
            "dataset must contain train, development, holdout and safety splits"
        )
    seen: set[str] = set()
    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": str(raw["dataset_id"]),
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "use_purpose": str(raw["use_purpose"]),
        "splits": {},
    }
    for split in SPLITS:
        rows = splits[split]
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or not rows:
            raise LifecycleError(f"dataset split {split} must be non-empty")
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise LifecycleError("dataset example must be an object")
            example_id = _require_string(row.get("example_id"), "example ID", 200)
            if example_id in seen:
                raise LifecycleError("dataset example IDs must be unique across splits")
            seen.add(example_id)
            input_value = row.get("input")
            expected = row.get("expected")
            if not isinstance(input_value, Mapping) or not isinstance(
                expected, Mapping
            ):
                raise LifecycleError(
                    "dataset input and expected result must be objects"
                )
            finding_ids = input_value.get("finding_ids")
            evidence = input_value.get("evidence")
            budget_tokens = input_value.get("budget_tokens")
            if (
                not isinstance(finding_ids, list)
                or not finding_ids
                or len(finding_ids) > 100
            ):
                raise LifecycleError("finding IDs must be a bounded non-empty list")
            if not isinstance(evidence, list) or len(evidence) > 500:
                raise LifecycleError("evidence must be a bounded list")
            evidence_ids = [
                str(item.get("evidence_id"))
                for item in evidence
                if isinstance(item, Mapping) and item.get("evidence_id")
            ]
            if len(evidence_ids) != len(set(evidence_ids)):
                raise LifecycleError("evidence IDs must be unique within an example")
            if (
                not isinstance(budget_tokens, int)
                or isinstance(budget_tokens, bool)
                or budget_tokens <= 0
            ):
                raise LifecycleError("example token budget must be positive")
            expected_refs = expected.get("evidence_refs")
            allowed_actions = expected.get("allowed_actions")
            if not isinstance(expected_refs, list) or any(
                str(ref) not in evidence_ids for ref in expected_refs
            ):
                raise LifecycleError(
                    "expected evidence references must exist in the example"
                )
            if not isinstance(allowed_actions, list) or any(
                not str(action).startswith("propose:") for action in allowed_actions
            ):
                raise LifecycleError("allowed actions must be non-executable proposals")
            min_confidence = expected.get("min_confidence", 0.0)
            if (
                not isinstance(min_confidence, (int, float))
                or not 0 <= float(min_confidence) <= 1
            ):
                raise LifecycleError("minimum confidence must be between zero and one")
            normalized_rows.append(
                {
                    "example_id": example_id,
                    "input": {
                        "finding_ids": [str(item) for item in finding_ids],
                        "evidence": [dict(item) for item in evidence],
                        "budget_tokens": budget_tokens,
                    },
                    "expected": {
                        "evidence_refs": [str(item) for item in expected_refs],
                        "allowed_actions": [str(item) for item in allowed_actions],
                        "min_confidence": float(min_confidence),
                    },
                }
            )
        normalized["splits"][split] = normalized_rows
    return normalized


def load_local_dataset(
    path: Path, *, tenant_id: str, deployment_id: str
) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise LifecycleError("dataset reference must resolve to a regular local file")
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("dataset could not be decoded") from exc
    if not isinstance(raw, Mapping):
        raise LifecycleError("dataset must be a JSON object")
    return validate_dataset(raw, tenant_id=tenant_id, deployment_id=deployment_id)


def evaluate_split(
    dataset: Mapping[str, Any],
    split_name: str,
    evaluator: Callable[[TriageInput], TriageOutput],
    thresholds: EvaluationThresholds,
) -> EvaluationResult:
    if split_name not in {"development", "holdout", "safety"}:
        raise LifecycleError(
            "only development, holdout and safety splits may establish quality"
        )
    rows = dataset["splits"][split_name]
    passed_rows = grounded_rows = safe_rows = 0
    used_tokens = 0
    failures: list[Mapping[str, str]] = []
    for row in rows:
        input_value = row["input"]
        expected = row["expected"]
        try:
            output = evaluator(
                TriageInput(
                    execution_id=f"evaluation:{row['example_id']}",
                    finding_ids=tuple(input_value["finding_ids"]),
                    evidence=tuple(input_value["evidence"]),
                    budget_tokens=int(input_value["budget_tokens"]),
                )
            )
            evidence_ids = {
                str(item["evidence_id"])
                for item in input_value["evidence"]
                if item.get("evidence_id")
            }
            output.validate(evidence_ids)
            used_tokens += output.input_tokens + output.output_tokens
            if used_tokens > sum(int(item["input"]["budget_tokens"]) for item in rows):
                raise LifecycleError("evaluation token budget was exceeded")
            grounded = set(expected["evidence_refs"]).issubset(
                set(output.evidence_refs)
            )
            safe = set(output.proposed_actions).issubset(
                set(expected["allowed_actions"])
            )
            confidence_ok = output.confidence >= float(expected["min_confidence"])
            grounded_rows += int(grounded)
            safe_rows += int(safe)
            passed_rows += int(grounded and safe and confidence_ok)
            if not (grounded and safe and confidence_ok):
                failures.append(
                    {"example_id": row["example_id"], "code": "expectation_mismatch"}
                )
        except (KeyError, TypeError, ValueError, RuntimeError, LifecycleError):
            failures.append(
                {"example_id": row["example_id"], "code": "evaluation_rejected"}
            )
    total = len(rows)
    metrics: dict[str, int | float] = {
        "examples": total,
        "pass_rate": passed_rows / total,
        "grounding_rate": grounded_rows / total,
        "action_safety_rate": safe_rows / total,
        "failure_rate": len(failures) / total,
        "used_tokens": used_tokens,
    }
    passed = (
        metrics["pass_rate"] >= thresholds.minimum_pass_rate
        and metrics["grounding_rate"] >= thresholds.minimum_grounding_rate
        and metrics["action_safety_rate"] >= thresholds.minimum_action_safety_rate
        and metrics["failure_rate"] <= thresholds.maximum_failure_rate
    )
    return EvaluationResult(metrics, tuple(failures), bool(passed), used_tokens)


def candidate_payload(
    *,
    tenant_id: str,
    deployment_id: str,
    program_id: str,
    base_program_digest: str,
    dataset_digest: str,
    optimizer_name: str,
    optimizer_config_digest: str,
    model_config_digest: str,
    dependency_digest: str,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    if optimizer_name not in {"bootstrap-few-shot", "miprov2"}:
        raise LifecycleError("optimizer is not approved")
    if any(
        not value.startswith("sha256:") or len(value) != 71
        for value in (
            base_program_digest,
            dataset_digest,
            optimizer_config_digest,
            model_config_digest,
            dependency_digest,
        )
    ):
        raise LifecycleError("candidate lineage digest is invalid")
    return {
        "schema_version": "autobot.dspy.candidate/v1",
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "program_id": program_id,
        "base_program_digest": base_program_digest,
        "dataset_digest": dataset_digest,
        "optimizer_name": optimizer_name,
        "optimizer_config_digest": optimizer_config_digest,
        "model_config_digest": model_config_digest,
        "dependency_digest": dependency_digest,
        "state": dict(state),
    }


def aggregate_receipt(
    *,
    tenant_id: str,
    deployment_id: str,
    evaluation_id: str,
    dataset_digest: str,
    program_digest: str,
    model_config_digest: str,
    metric_contract_digest: str,
    split_name: str,
    result: EvaluationResult,
    sign: Callable[[Mapping[str, Any]], str],
    completed_at: datetime | None = None,
) -> dict[str, Any]:
    """Return a fixed-shape export with no examples, traces, prompts or refs."""
    if split_name not in {"development", "holdout", "safety"}:
        raise LifecycleError("receipt split is not exportable")
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_VERSION,
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "evaluation_id": str(uuid.UUID(evaluation_id)),
        "dataset_digest": dataset_digest,
        "program_digest": program_digest,
        "model_config_digest": model_config_digest,
        "metric_contract_digest": metric_contract_digest,
        "split_name": split_name,
        "metrics": dict(result.metrics),
        "passed": result.passed,
        "completed_at": (completed_at or datetime.now(timezone.utc)).isoformat(),
    }
    receipt["signature"] = sign(receipt)
    return receipt


def write_candidate(path: Path, payload: Mapping[str, Any]) -> str:
    """Persist declarative JSON state only; executable pickle is forbidden."""
    if path.suffix.lower() != ".json":
        raise LifecycleError("candidate artifacts must use declarative JSON state")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_json(payload)
    path.write_bytes(raw)
    return digest_bytes(raw)


def metric_contract_digest() -> str:
    source = Path(__file__).read_bytes()
    return digest_bytes(source)
