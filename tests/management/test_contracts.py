from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from services.management.contracts import BYOCHealthEvent, DeploymentManifest

ROOT = Path(__file__).resolve().parents[2]


def test_manifest_example_matches_python_contract() -> None:
    value = json.loads(
        (
            ROOT / "docs/architecture/contracts/deployment-manifest.example.json"
        ).read_text()
    )
    held = DeploymentManifest.model_validate(value)
    assert held.generation == held.expected_generation + 1


def test_manifest_rejects_weaker_isolation_and_unknown_fields() -> None:
    value = json.loads(
        (
            ROOT / "docs/architecture/contracts/deployment-manifest.example.json"
        ).read_text()
    )
    value["isolation"]["execution"] = "shared-workers"
    with pytest.raises(ValueError):
        DeploymentManifest.model_validate(value)


def test_byoc_manifest_keeps_dedicated_runtime_boundaries() -> None:
    value = json.loads(
        (
            ROOT / "docs/architecture/contracts/deployment-manifest.example.json"
        ).read_text()
    )
    value["mode"] = "byoc"
    held = DeploymentManifest.model_validate(value)
    assert held.mode == "byoc"
    value["isolation"]["database"] = "shared-rows"
    with pytest.raises(ValueError):
        DeploymentManifest.model_validate(value)
    value = json.loads(
        (
            ROOT / "docs/architecture/contracts/deployment-manifest.example.json"
        ).read_text()
    )
    value["placement"]["account_id"] = "111111111111"
    with pytest.raises(ValueError):
        DeploymentManifest.model_validate(value)


def test_postman_collection_is_derived_from_every_openapi_operation() -> None:
    openapi = yaml.safe_load(
        (ROOT / "contracts/management-plane.openapi.yaml").read_text()
    )
    collection = json.loads(
        (ROOT / "contracts/postman/management-plane.collection.json").read_text()
    )
    expected = {
        operation["operationId"]
        for path_item in openapi["paths"].values()
        for method, operation in path_item.items()
        if method in {"get", "post", "put", "patch", "delete"}
    }
    assert {item["name"] for item in collection["item"]} == expected


def test_openapi_embeds_the_authoritative_deployment_manifest_schema() -> None:
    source = json.loads(
        (ROOT / "contracts/deployment-manifest.schema.json").read_text()
    )
    source.pop("$schema")
    source.pop("$id")
    encoded = json.dumps(source).replace(
        "#/$defs/", "#/components/schemas/DeploymentManifest/$defs/"
    )
    expected = json.loads(encoded)
    openapi = yaml.safe_load(
        (ROOT / "contracts/management-plane.openapi.yaml").read_text()
    )
    assert openapi["components"]["schemas"]["DeploymentManifest"] == expected


def test_byoc_dspy_receipt_is_fixed_and_bound_to_its_event_kind() -> None:
    event = {
        "incarnation": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "sequence": 1,
        "event_kind": "dspy_evaluation",
        "occurred_at": "2026-10-12T12:00:00Z",
        "revocation_epoch": 1,
        "payload": {
            "status": "healthy",
            "observed_generation": 1,
            "dspy_evaluation": {
                "schema_version": "autobot.dspy.evaluation-receipt/v1",
                "tenant_id": "tenant-a",
                "deployment_id": "deployment-a",
                "evaluation_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "dataset_digest": "sha256:" + "1" * 64,
                "program_digest": "sha256:" + "2" * 64,
                "model_config_digest": "sha256:" + "3" * 64,
                "metric_contract_digest": "sha256:" + "4" * 64,
                "split_name": "holdout",
                "metrics": {"pass_rate": 1.0},
                "passed": True,
                "completed_at": "2026-10-12T11:59:00Z",
                "signature": "s" * 64,
            },
        },
        "signature": "e" * 64,
    }
    assert BYOCHealthEvent.model_validate(event).payload.dspy_evaluation is not None
    event["event_kind"] = "heartbeat"
    with pytest.raises(ValueError, match="bound only to its event kind"):
        BYOCHealthEvent.model_validate(event)


def test_byoc_dspy_receipt_rejects_customer_examples_and_traces() -> None:
    receipt_schema = yaml.safe_load(
        (ROOT / "contracts/management-plane.openapi.yaml").read_text()
    )["components"]["schemas"]["BYOCDSPyEvaluationReceipt"]
    assert receipt_schema["additionalProperties"] is False
    assert "examples" not in receipt_schema["properties"]
    assert "traces" not in receipt_schema["properties"]
