from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def _collection_operations() -> set[tuple[str, str]]:
    collection = json.loads(
        (ROOT / "contracts/postman/managed-agent-runs.collection.json").read_text()
    )
    operations: set[tuple[str, str]] = set()
    for item in collection["item"]:
        request = item["request"]
        raw = request["url"]["raw"]
        path = raw.replace("{{baseUrl}}", "").replace("{{gatewayUrl}}", "")
        path = path.replace("{{runId}}", "{run_id}")
        operations.add((request["method"].lower(), path))
    return operations


def test_postman_collection_covers_every_managed_openapi_operation() -> None:
    spec = yaml.safe_load(
        (ROOT / "contracts/managed-agent-runs.openapi.yaml").read_text()
    )
    expected = {
        (method, path)
        for path, path_item in spec["paths"].items()
        for method in path_item
        if method in {"get", "post", "put", "patch", "delete"}
    }
    assert expected <= _collection_operations()


def test_tool_grant_contract_requires_every_execution_binding() -> None:
    spec = yaml.safe_load(
        (ROOT / "contracts/managed-agent-runs.openapi.yaml").read_text()
    )
    required = set(spec["components"]["schemas"]["ToolGrant"]["required"])
    assert {
        "execution_id",
        "tenant_id",
        "deployment_id",
        "deployment_incarnation",
        "workflow_id",
        "workflow_digest",
        "program_id",
        "program_digest",
        "workload_key_id",
        "claim_jti",
        "policy_version",
        "revocation_epoch",
        "action",
        "resource",
        "argument_digest",
        "max_rows",
        "timeout_ms",
    } <= required


def test_managed_context_contract_requires_deployment_incarnation() -> None:
    schema = json.loads(
        (ROOT / "contracts/managed-execution.schema.json").read_text()
    )
    required = set(schema["properties"]["admission"]["properties"]["context"]["required"])
    assert "deployment_incarnation" in required
