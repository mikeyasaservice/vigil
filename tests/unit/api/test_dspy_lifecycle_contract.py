from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

from services.reasoner.lifecycle import candidate_payload

ROOT = Path(__file__).resolve().parents[3]


def test_postman_collection_covers_every_dspy_openapi_operation() -> None:
    spec = yaml.safe_load((ROOT / "contracts/dspy-lifecycle.openapi.yaml").read_text())
    collection = json.loads(
        (ROOT / "contracts/postman/dspy-lifecycle.collection.json").read_text()
    )
    operations = {
        item["operationId"]
        for path in spec["paths"].values()
        for method, item in path.items()
        if method in {"get", "post", "put", "patch", "delete"}
    }
    assert {item["name"] for item in collection["item"]} == operations


def test_lifecycle_contract_has_no_dataset_upload_or_latest_alias() -> None:
    spec_text = (ROOT / "contracts/dspy-lifecycle.openapi.yaml").read_text()
    assert "example" not in spec_text.lower()
    assert "prompt" not in spec_text.lower()
    assert "latest" not in spec_text.lower()


def test_json_schema_uses_autobot_trust_domain() -> None:
    schema = json.loads((ROOT / "contracts/dspy-lifecycle.schema.json").read_text())
    assert schema["$id"].startswith("https://schemas.autobot.security/")


def test_candidate_artifact_matches_shared_lifecycle_schema() -> None:
    schema = json.loads((ROOT / "contracts/dspy-lifecycle.schema.json").read_text())
    candidate = candidate_payload(
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
    jsonschema.validate(candidate, {**schema, "$ref": "#/$defs/candidate"})
