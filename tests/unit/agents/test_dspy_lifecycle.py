from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from core.agents.managed_execution import Ed25519Signer
from services.reasoner.contracts import TriageOutput
from services.reasoner.evaluate import _load_candidate
from services.reasoner.lifecycle import (
    EvaluationThresholds,
    LifecycleError,
    aggregate_receipt,
    candidate_payload,
    digest,
    evaluate_split,
    validate_dataset,
    write_candidate,
)


def dataset(tenant: str = "tenant-a") -> dict:
    def row(identifier: str) -> dict:
        return {
            "example_id": identifier,
            "input": {
                "finding_ids": [f"finding-{identifier}"],
                "evidence": [
                    {"evidence_id": f"evidence-{identifier}", "summary": "café"}
                ],
                "budget_tokens": 100,
            },
            "expected": {
                "evidence_refs": [f"evidence-{identifier}"],
                "allowed_actions": ["propose:review"],
                "min_confidence": 0.5,
            },
        }

    return {
        "schema_version": "autobot.dspy.dataset/v1",
        "dataset_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "deployment_id": "deployment-a",
        "use_purpose": "fixed synthetic triage qualification",
        "splits": {
            name: [row(name)] for name in ("train", "development", "holdout", "safety")
        },
    }


def test_dataset_is_owned_split_and_unicode_canonical() -> None:
    first = validate_dataset(
        dataset(), tenant_id="tenant-a", deployment_id="deployment-a"
    )
    reordered = json.loads(json.dumps(first, ensure_ascii=False))
    assert digest(first) == digest(reordered)
    with pytest.raises(LifecycleError, match="authenticated deployment"):
        validate_dataset(
            dataset("tenant-b"), tenant_id="tenant-a", deployment_id="deployment-a"
        )
    first["splits"]["safety"] = []
    with pytest.raises(LifecycleError, match="non-empty"):
        validate_dataset(first, tenant_id="tenant-a", deployment_id="deployment-a")


def test_evaluation_requires_grounded_safe_expected_output() -> None:
    value = validate_dataset(
        dataset(), tenant_id="tenant-a", deployment_id="deployment-a"
    )
    thresholds = EvaluationThresholds(1, 1, 1, 0)

    def valid(input_value):
        evidence_id = input_value.evidence[0]["evidence_id"]
        return TriageOutput(
            ("hypothesis",), (evidence_id,), 0.8, (), ("propose:review",), 10, 5
        )

    result = evaluate_split(value, "holdout", valid, thresholds)
    assert result.passed
    assert result.metrics == {
        "examples": 1,
        "pass_rate": 1,
        "grounding_rate": 1,
        "action_safety_rate": 1,
        "failure_rate": 0,
        "used_tokens": 15,
    }

    def invented(_):
        return TriageOutput(
            ("hypothesis",), ("foreign-evidence",), 0.8, (), ("delete:host",)
        )

    rejected = evaluate_split(value, "safety", invented, thresholds)
    assert not rejected.passed
    assert rejected.failures[0]["code"] == "evaluation_rejected"


def test_receipt_has_fixed_aggregate_shape_and_no_customer_examples() -> None:
    value = validate_dataset(
        dataset(), tenant_id="tenant-a", deployment_id="deployment-a"
    )
    result = evaluate_split(
        value,
        "holdout",
        lambda input_value: TriageOutput(
            ("h",),
            (input_value.evidence[0]["evidence_id"],),
            0.7,
            (),
            ("propose:review",),
        ),
        EvaluationThresholds(1, 1, 1, 0),
    )
    receipt = aggregate_receipt(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        evaluation_id=str(uuid.uuid4()),
        dataset_digest=digest(value),
        program_digest="sha256:" + "2" * 64,
        model_config_digest="sha256:" + "3" * 64,
        metric_contract_digest="sha256:" + "4" * 64,
        split_name="holdout",
        result=result,
        sign=lambda payload: "signed-" + digest(payload),
    )
    encoded = json.dumps(receipt)
    assert "finding-" not in encoded
    assert "evidence-" not in encoded
    assert "café" not in encoded
    assert "trace" not in encoded
    assert set(receipt) == {
        "schema_version",
        "tenant_id",
        "deployment_id",
        "evaluation_id",
        "dataset_digest",
        "program_digest",
        "model_config_digest",
        "metric_contract_digest",
        "split_name",
        "metrics",
        "passed",
        "completed_at",
        "signature",
    }


def test_candidate_is_declarative_digest_bound_json(tmp_path: Path) -> None:
    payload = candidate_payload(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        program_id="triage-dspy-v1",
        base_program_digest="sha256:" + "1" * 64,
        dataset_digest="sha256:" + "2" * 64,
        optimizer_name="miprov2",
        optimizer_config_digest="sha256:" + "3" * 64,
        model_config_digest="sha256:" + "4" * 64,
        dependency_digest="sha256:" + "5" * 64,
        state={"predictors": [{"demos": []}]},
    )
    path = tmp_path / "candidate.json"
    held = write_candidate(path, payload)
    assert held.startswith("sha256:")
    assert json.loads(path.read_text()) == payload
    with pytest.raises(LifecycleError, match="declarative JSON"):
        write_candidate(tmp_path / "candidate.pkl", payload)


def test_candidate_load_requires_digest_signature_and_deployment_binding(
    tmp_path: Path,
) -> None:
    payload = candidate_payload(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        program_id="triage-dspy-v1",
        base_program_digest="sha256:" + "1" * 64,
        dataset_digest="sha256:" + "2" * 64,
        optimizer_name="miprov2",
        optimizer_config_digest="sha256:" + "3" * 64,
        model_config_digest="sha256:" + "4" * 64,
        dependency_digest="sha256:" + "5" * 64,
        state={"predictors": [{"demos": []}]},
    )
    path = tmp_path / "candidate.json"
    held_digest = write_candidate(path, payload)
    signer = Ed25519Signer()
    signature = signer.sign(payload)
    held = _load_candidate(
        path,
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        expected_digest=held_digest,
        signature=signature,
        public_key=signer.verifier().public_key,
    )
    assert held["state"] == payload["state"]
    with pytest.raises(LifecycleError, match="deployment binding"):
        _load_candidate(
            path,
            tenant_id="tenant-b",
            deployment_id="deployment-a",
            expected_digest=held_digest,
            signature=signature,
            public_key=signer.verifier().public_key,
        )
    with pytest.raises(LifecycleError, match="signature"):
        _load_candidate(
            path,
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            expected_digest=held_digest,
            signature="invalid",
            public_key=signer.verifier().public_key,
        )
