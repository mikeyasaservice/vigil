#!/usr/bin/env python3
"""Verify tenant resources are gone or cryptographic keys are pending deletion."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))


def aws(tenant: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        AWS_CONFIG_FILE=str(ROOT / "aws-config"),
        AWS_PROFILE=os.getenv(
            "VIGIL_AWS_VERIFIER_PROFILE", f"vigil-tenant-{tenant}"
        ),
        AWS_REGION="us-east-1",
        AWS_DEFAULT_REGION="us-east-1",
        AWS_EC2_METADATA_DISABLED="true",
    )
    return subprocess.run(["aws", *args], env=env, text=True, capture_output=True, check=False)


def absent(result: subprocess.CompletedProcess[str]) -> bool:
    message = (result.stdout + result.stderr).lower()
    return result.returncode != 0 and any(
        value in message
        for value in (
            "notfound",
            "not found",
            "cannot be found",
            "does not exist",
            "nosuchbucket",
            "nosuchentity",
            "nonexistentqueue",
        )
    )


def eventually_absent(tenant: str, *args: str) -> bool:
    """Allow bounded AWS control-plane propagation without accepting a timeout."""
    for attempt in range(10):
        if absent(aws(tenant, *args)):
            return True
        if attempt < 9:
            time.sleep(3)
    return False


def main(tenant: str) -> int:
    outputs = json.loads((ROOT / f"tenant-{tenant}" / "outputs.pre-offboard.json").read_text())
    checks: dict[str, bool] = {}
    checks["eks_cluster_deleted"] = absent(
        aws(tenant, "eks", "describe-cluster", "--name", outputs["clusterName"])
    )
    checks["aurora_cluster_deleted"] = absent(
        aws(tenant, "rds", "describe-db-clusters", "--db-cluster-identifier", outputs["databaseIdentifier"])
    )
    snapshots = aws(
        tenant,
        "rds",
        "describe-db-cluster-snapshots",
        "--snapshot-type",
        "manual",
        "--output",
        "json",
    )
    if snapshots.returncode == 0:
        checks["manual_aurora_snapshots_deleted"] = not any(
            item.get("DBClusterIdentifier") == outputs["databaseIdentifier"]
            for item in json.loads(snapshots.stdout).get("DBClusterSnapshots", [])
        )
    else:
        checks["manual_aurora_snapshots_deleted"] = False
    cache = aws(
        tenant,
        "elasticache",
        "describe-serverless-caches",
        "--serverless-cache-name",
        outputs["redisIdentifier"],
        "--output",
        "json",
    )
    checks["valkey_cache_deleted"] = absent(cache)
    checks["vpc_deleted"] = absent(
        aws(tenant, "ec2", "describe-vpcs", "--vpc-ids", outputs["vpcId"])
    )
    checks["evidence_bucket_deleted"] = aws(
        tenant, "s3api", "head-bucket", "--bucket", outputs["evidenceBucket"]
    ).returncode != 0
    secret = aws(
        tenant,
        "secretsmanager",
        "describe-secret",
        "--secret-id",
        outputs["runtimeSecretArn"],
        "--output",
        "json",
    )
    if secret.returncode == 0:
        checks["runtime_secret_deleted_or_scheduled"] = "DeletedDate" in json.loads(secret.stdout)
    else:
        checks["runtime_secret_deleted_or_scheduled"] = absent(secret)
    key = aws(tenant, "kms", "describe-key", "--key-id", outputs["keyArn"], "--output", "json")
    if key.returncode == 0:
        checks["kms_key_deleted_or_pending"] = (
            json.loads(key.stdout).get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
        )
    else:
        checks["kms_key_deleted_or_pending"] = absent(key)
    repository_checks = []
    for repository in outputs["imageRepositories"].values():
        name = repository.split("amazonaws.com/", 1)[1]
        repository_checks.append(
            absent(aws(tenant, "ecr", "describe-repositories", "--repository-names", name))
        )
    checks["ecr_repositories_deleted"] = all(repository_checks)
    role_name = outputs["externalSecretsRoleArn"].split("/", 1)[1]
    checks["workload_role_deleted"] = eventually_absent(
        tenant, "iam", "get-role", "--role-name", role_name
    )
    report = {
        "tenant": tenant,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "scope": "real AWS dedicated tenant offboarding",
        "checks": checks,
        "result": "passed" if all(checks.values()) else "failed",
        "retention_note": "Secrets and KMS keys may remain only in AWS scheduled-deletion state.",
    }
    destination = ROOT / "evidence" / f"offboard-{tenant}.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": report["result"], "evidence": str(destination), "checks": checks}))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"a", "b"}:
        raise SystemExit("usage: offboard-verify.py [a|b]")
    raise SystemExit(main(sys.argv[1]))
