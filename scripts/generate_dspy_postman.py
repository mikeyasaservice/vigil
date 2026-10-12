#!/usr/bin/env python3
"""Generate the filesystem-local DSPy lifecycle Postman collection."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "contracts" / "dspy-lifecycle.openapi.yaml"
OUTPUT = ROOT / "contracts" / "postman" / "dspy-lifecycle.collection.json"

EXAMPLES = {
    "registerDSPyDataset": {
        "dataset_id": "00000000-0000-4000-8000-000000000010",
        "name": "synthetic-triage",
        "version": 1,
        "object_ref": "local:datasets/synthetic-triage-v1.json",
        "content_digest": "sha256:" + "1" * 64,
        "schema_digest": "sha256:" + "2" * 64,
        "split_manifest": {"train": 10, "development": 5, "holdout": 5, "safety": 5},
        "use_purpose": "Synthetic triage program qualification",
        "sensitivity": "synthetic",
        "retention_policy_ref": "local:retention/default",
        "access_policy_ref": "local:access/reasoner-only",
    },
    "createDSPyEvaluation": {
        "dataset_id": "00000000-0000-4000-8000-000000000010",
        "program_id": "triage-dspy-v1",
        "program_digest": "sha256:" + "3" * 64,
        "model_config_digest": "sha256:" + "4" * 64,
        "evaluator_digest": "sha256:" + "5" * 64,
        "split_name": "holdout",
        "seed": 9,
        "thresholds": {
            "minimum_pass_rate": 0.9,
            "minimum_grounding_rate": 1,
            "minimum_action_safety_rate": 1,
            "maximum_failure_rate": 0.1,
        },
        "execution_location": "tenant-local",
        "max_tokens": 100000,
        "max_cost_microusd": 1000000,
    },
    "createDSPyOptimization": {
        "dataset_id": "00000000-0000-4000-8000-000000000010",
        "base_program_id": "triage-dspy-v1",
        "base_program_digest": "sha256:" + "3" * 64,
        "optimizer_name": "miprov2",
        "optimizer_config": {"auto": "light", "num_threads": 1},
        "model_config_digest": "sha256:" + "4" * 64,
        "dependency_digest": "sha256:" + "6" * 64,
        "seed": 9,
        "max_tokens": 100000,
        "max_cost_microusd": 1000000,
        "lineage_classification": "synthetic",
    },
    "requestDSPyPromotion": {
        "optimization_id": "00000000-0000-4000-8000-000000000020",
        "holdout_evaluation_id": "00000000-0000-4000-8000-000000000030",
        "target_stage": "staged",
    },
    "approveDSPyPromotion": {"request_digest": "sha256:" + "7" * 64},
    "requestDSPyRollback": {
        "program_id": "triage-dspy-v1",
        "target_program_digest": "sha256:" + "8" * 64,
    },
    "approveDSPyRollback": {"request_digest": "sha256:" + "9" * 64},
}


def main() -> None:
    spec = yaml.safe_load(SPEC.read_text())
    items = []
    for path, path_item in spec["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if operation is None:
                continue
            operation_id = operation["operationId"]
            url_path = path.replace("{promotion_id}", "{{promotionId}}").replace(
                "{rollback_id}", "{{rollbackId}}"
            )
            request = {
                "method": method.upper(),
                "header": [{"key": "Authorization", "value": "Bearer {{accessToken}}"}],
                "url": {
                    "raw": "{{baseUrl}}" + url_path,
                    "host": ["{{baseUrl}}"],
                    "path": [part for part in url_path.split("/") if part],
                },
            }
            if operation_id in EXAMPLES:
                request["header"].append(
                    {"key": "Content-Type", "value": "application/json"}
                )
                request["body"] = {
                    "mode": "raw",
                    "raw": json.dumps(EXAMPLES[operation_id], indent=2),
                }
            items.append(
                {
                    "name": operation_id,
                    "request": request,
                    "event": [
                        {
                            "listen": "test",
                            "script": {
                                "exec": [
                                    "pm.test('authenticated lifecycle boundary responds', () => pm.expect(pm.response.code).to.be.below(500));"
                                ]
                            },
                        }
                    ],
                }
            )
    collection = {
        "info": {
            "name": "Autobot DSPy lifecycle (local)",
            "description": "Generated from contracts/dspy-lifecycle.openapi.yaml. Keep tenant credentials and datasets local.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "baseUrl", "value": "http://localhost:6987"},
            {"key": "accessToken", "value": ""},
            {"key": "promotionId", "value": "00000000-0000-4000-8000-000000000040"},
            {"key": "rollbackId", "value": "00000000-0000-4000-8000-000000000050"},
        ],
        "item": items,
    }
    OUTPUT.write_text(json.dumps(collection, indent=2) + "\n")


if __name__ == "__main__":
    main()
