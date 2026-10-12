#!/usr/bin/env python3
"""Verify the temporary production-qualification deployer roles are deleted."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
PROFILE = os.getenv("AWS_PROFILE", "pulumi")
REGION = os.getenv("AWS_REGION", "us-east-1")


def get_role(role_name: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        AWS_PROFILE=PROFILE,
        AWS_REGION=REGION,
        AWS_DEFAULT_REGION=REGION,
        AWS_EC2_METADATA_DISABLED="true",
    )
    return subprocess.run(
        ["aws", "iam", "get-role", "--role-name", role_name],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def eventually_deleted(role_name: str) -> bool:
    for attempt in range(10):
        result = get_role(role_name)
        message = (result.stdout + result.stderr).lower()
        if result.returncode != 0 and (
            "nosuchentity" in message or "cannot be found" in message
        ):
            return True
        if attempt < 9:
            time.sleep(3)
    return False


def main() -> int:
    outputs = json.loads((ROOT / "bootstrap" / "outputs.pre-offboard.json").read_text())
    checks = {
        f"tenant_{tenant}_deployer_role_deleted": eventually_deleted(
            arn.rsplit("/", 1)[-1]
        )
        for tenant, arn in outputs["roleArns"].items()
    }
    report = {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "scope": "real AWS qualification bootstrap offboarding",
        "checks": checks,
        "result": "passed" if all(checks.values()) else "failed",
    }
    destination = ROOT / "evidence" / "offboard-bootstrap.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": report["result"], "evidence": str(destination), "checks": checks}))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
