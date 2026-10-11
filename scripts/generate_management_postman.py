#!/usr/bin/env python3
"""Generate the filesystem-local Phase 3 collection from its OpenAPI paths."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "contracts" / "management-plane.openapi.yaml"
OUTPUT = ROOT / "contracts" / "postman" / "management-plane.collection.json"


def variable_path(path: str) -> str:
    return path.replace("{deployment_id}", "{{deploymentId}}").replace("{operation_id}", "{{operationId}}")


def main() -> None:
    document = yaml.safe_load(SPEC.read_text())
    items: list[dict] = []
    for path, path_item in document["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if operation is None:
                continue
            headers = [{"key": "Accept", "value": "application/json"}]
            security = operation.get("security", [])
            if any("operatorBearer" in requirement for requirement in security):
                headers.append({"key": "Authorization", "value": "Bearer {{operatorToken}}"})
            if any("reconcilerWorkload" in requirement for requirement in security):
                headers.append({"key": "X-Vigil-Runner-Id", "value": "{{runnerId}}"})
            if "requestBody" in operation:
                headers.append({"key": "Content-Type", "value": "application/json"})
            if operation["operationId"] == "requestDeploymentOperation":
                headers.append({"key": "Idempotency-Key", "value": "{{idempotencyKey}}"})
            target = variable_path(path)
            request: dict = {
                "method": method.upper(),
                "header": headers,
                "url": {"raw": "{{baseUrl}}" + target, "host": ["{{baseUrl}}"], "path": target.strip("/").split("/")},
            }
            if "requestBody" in operation:
                request["body"] = {"mode": "raw", "raw": "{{" + operation["operationId"] + "Body}}"}
            items.append(
                {
                    "name": operation["operationId"],
                    "request": request,
                    "event": [
                        {
                            "listen": "test",
                            "script": {
                                "exec": [
                                    "pm.test('response is JSON', () => pm.response.to.be.json);",
                                    "pm.test('server did not fail open', () => pm.expect(pm.response.code).to.not.equal(500));",
                                ]
                            },
                        }
                    ],
                }
            )
    collection = {
        "info": {
            "name": "Vigil Management Plane (local)",
            "description": "Generated from contracts/management-plane.openapi.yaml. Keep credentials in a local environment; do not publish this collection.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "baseUrl", "value": "http://127.0.0.1:8090"},
            {"key": "deploymentId", "value": "deployment-example-a"},
            {"key": "operationId", "value": "00000000-0000-4000-8000-000000000000"},
            {"key": "operatorToken", "value": ""},
            {"key": "runnerId", "value": "reconciler-local-1"},
            {"key": "idempotencyKey", "value": "local-provision-1"},
        ],
        "item": items,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(collection, indent=2) + "\n")


if __name__ == "__main__":
    main()
