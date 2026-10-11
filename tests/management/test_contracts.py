from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from services.management.contracts import DeploymentManifest


ROOT = Path(__file__).resolve().parents[2]


def test_manifest_example_matches_python_contract() -> None:
    value = json.loads((ROOT / "docs/architecture/contracts/deployment-manifest.example.json").read_text())
    held = DeploymentManifest.model_validate(value)
    assert held.generation == held.expected_generation + 1


def test_manifest_rejects_weaker_isolation_and_unknown_fields() -> None:
    value = json.loads((ROOT / "docs/architecture/contracts/deployment-manifest.example.json").read_text())
    value["isolation"]["execution"] = "shared-workers"
    with pytest.raises(ValueError):
        DeploymentManifest.model_validate(value)
    value = json.loads((ROOT / "docs/architecture/contracts/deployment-manifest.example.json").read_text())
    value["placement"]["account_id"] = "111111111111"
    with pytest.raises(ValueError):
        DeploymentManifest.model_validate(value)


def test_postman_collection_is_derived_from_every_openapi_operation() -> None:
    openapi = yaml.safe_load((ROOT / "contracts/management-plane.openapi.yaml").read_text())
    collection = json.loads((ROOT / "contracts/postman/management-plane.collection.json").read_text())
    expected = {
        operation["operationId"]
        for path_item in openapi["paths"].values()
        for method, operation in path_item.items()
        if method in {"get", "post", "put", "patch", "delete"}
    }
    assert {item["name"] for item in collection["item"]} == expected
