#!/usr/bin/env python3
"""Independently verify that the real-AWS BYOC qualification stack is offboarded."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.getenv("AUTOBOT_BYOC_QUALIFICATION_ROOT", "/tmp/autobot-byoc-qualification"))
PROFILE = os.getenv("AWS_PROFILE", "pulumi")
REGION = os.getenv("AWS_REGION", "us-east-1")


def aws(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        AWS_PROFILE=PROFILE,
        AWS_REGION=REGION,
        AWS_DEFAULT_REGION=REGION,
        AWS_EC2_METADATA_DISABLED="true",
    )
    return subprocess.run(["aws", *args], env=env, text=True, capture_output=True, check=False)


def missing(result: subprocess.CompletedProcess[str], *markers: str) -> bool:
    message = (result.stdout + result.stderr).lower()
    return result.returncode != 0 and any(marker.lower() in message for marker in markers)


def main() -> int:
    outputs = json.loads((ROOT / "outputs.pre-offboard.json").read_text())
    checks: dict[str, bool] = {}
    for name in ("evidenceBucket", "backupBucket"):
        result = aws("s3api", "head-bucket", "--bucket", outputs[name])
        checks[f"{name}_deleted"] = result.returncode != 0

    queue = aws(
        "sqs",
        "get-queue-attributes",
        "--queue-url",
        outputs["executionQueueUrl"],
        "--attribute-names",
        "All",
    )
    checks["execution_queue_deleted"] = missing(
        queue, "NonExistentQueue", "does not exist", "InvalidAddress"
    )

    secret = aws(
        "secretsmanager",
        "describe-secret",
        "--secret-id",
        outputs["integrationSecretArn"],
        "--output",
        "json",
    )
    if secret.returncode == 0:
        checks["integration_secret_deleted_or_scheduled"] = "DeletedDate" in json.loads(secret.stdout)
    else:
        checks["integration_secret_deleted_or_scheduled"] = missing(
            secret, "ResourceNotFoundException", "not found"
        )

    key = aws("kms", "describe-key", "--key-id", outputs["keyArn"], "--output", "json")
    if key.returncode == 0:
        checks["customer_key_deleted_or_pending"] = (
            json.loads(key.stdout).get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
        )
    else:
        checks["customer_key_deleted_or_pending"] = missing(
            key, "NotFoundException", "not found"
        )

    report = {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "scope": "real AWS same-account BYOC development qualification offboarding",
        "checks": checks,
        "result": "passed" if all(checks.values()) else "failed",
        "retention_note": "Secrets and KMS keys may remain only in AWS scheduled-deletion state.",
    }
    destination = ROOT / "evidence" / "byoc-offboard.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": report["result"], "evidence": str(destination), "checks": checks}))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
