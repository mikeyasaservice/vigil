#!/usr/bin/env python3
"""Exercise real Aurora recovery and S3 versioned deletion in tenant A's AWS plane."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID


def load_runtime() -> ModuleType:
    path = Path(__file__).with_name("runtime-qualify.py")
    spec = importlib.util.spec_from_file_location("autobot_runtime_qualify", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime qualification helpers are unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runtime = load_runtime()


def aws(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["aws", *args], env=runtime.aws_env("a"), text=True,
        capture_output=True, check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise RuntimeError(f"AWS command failed: {' | '.join(detail[-5:])}")
    return result


def aws_json(*args: str) -> Any:
    result = aws(*args, "--output", "json")
    return json.loads(result.stdout)


DATABASE_STATE = r'''
import json
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    state={
      "finding_canary":session.execute(text("SELECT description FROM findings WHERE finding_id='qualification-collision'")).scalar_one(),
      "managed_runs":session.execute(text("SELECT count(*) FROM managed_runs")).scalar_one(),
      "agent_events":session.execute(text("SELECT count(*) FROM agent_events")).scalar_one(),
      "memberships":session.execute(text("SELECT count(*) FROM managed_memberships")).scalar_one(),
      "programs":session.execute(text("SELECT count(*) FROM managed_program_registry")).scalar_one(),
      "run_digest":session.execute(text("""
        SELECT md5(COALESCE(string_agg(run_id::text || ':' || status, ',' ORDER BY run_id),''))
        FROM managed_runs
      """)).scalar_one(),
      "ledger_digest":session.execute(text("""
        SELECT md5(COALESCE(string_agg(run_id::text || ':' || seq::text || ':' || kind, ',' ORDER BY run_id,seq),''))
        FROM agent_events
      """)).scalar_one(),
    }
print(json.dumps(state, default=str))
'''


def database_state(host: str | None = None) -> dict[str, Any]:
    args = ["exec", "-i", "-n", "vigil", "deploy/vigil-backend", "-c", "backend", "--"]
    if host is not None:
        args.extend(["env", f"POSTGRES_HOST={host}"])
    args.extend(["python", "-"])
    result = runtime.kubectl("a", *args, input_text=DATABASE_STATE)
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> int:
    EVIDENCE.mkdir(parents=True, mode=0o700)
    outputs = json.loads((ROOT / "tenant-a" / "outputs.json").read_text())
    source_cluster = outputs["databaseIdentifier"]
    bucket = outputs["evidenceBucket"]
    suffix = RUN_ID.lower()
    snapshot = f"autobot-qual-a-{suffix}"
    restored_cluster = f"autobot-qual-a-restore-{suffix}"
    restored_instance = f"autobot-qual-a-restore-instance-{suffix}"
    security_group: str | None = None
    node_sg: str | None = None
    ingress_open = False
    object_key = f"qualification/{RUN_ID}/deletion-canary.json"
    object_version: str | None = None
    report: dict[str, Any] = {
        "run_id": RUN_ID,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "assertions": {},
        "resources": {"source_cluster": source_cluster, "bucket": bucket},
    }
    try:
        source = database_state()
        cluster = aws_json("rds", "describe-db-clusters", "--db-cluster-identifier", source_cluster)["DBClusters"][0]
        source_sg = cluster["VpcSecurityGroups"][0]["VpcSecurityGroupId"]
        subnet_group = cluster["DBSubnetGroup"]
        engine_version = cluster["EngineVersion"]
        kms_key = cluster["KmsKeyId"]
        vpc_id = outputs["vpcId"]
        permissions = aws_json("ec2", "describe-security-groups", "--group-ids", source_sg)["SecurityGroups"][0]["IpPermissions"]
        node_groups = [
            pair["GroupId"]
            for permission in permissions if permission.get("FromPort") == 5432
            for pair in permission.get("UserIdGroupPairs", []) if pair.get("GroupId")
        ]
        if len(node_groups) != 1:
            raise RuntimeError("source database does not expose one exact EKS node security group")
        node_sg = node_groups[0]

        with tempfile.NamedTemporaryFile("w", prefix="autobot-recovery-", suffix=".json", delete=False) as payload:
            json.dump({"run_id": RUN_ID, "tenant": "tenant-qual-a", "canary": "AUTOBOT-DELETE-ME"}, payload)
            payload_path = Path(payload.name)
        try:
            put = aws_json("s3api", "put-object", "--bucket", bucket, "--key", object_key, "--body", str(payload_path))
        finally:
            payload_path.unlink(missing_ok=True)
        object_version = put.get("VersionId")
        head = aws_json("s3api", "head-object", "--bucket", bucket, "--key", object_key, "--version-id", object_version)
        report["evidence_object"] = {
            "key": object_key,
            "version_id": object_version,
            "encryption": head.get("ServerSideEncryption"),
            "kms_key_id": head.get("SSEKMSKeyId"),
        }

        aws("rds", "create-db-cluster-snapshot", "--db-cluster-identifier", source_cluster,
            "--db-cluster-snapshot-identifier", snapshot,
            "--tags", f"Key=autobot.io/qualification,Value={RUN_ID}")
        aws("rds", "wait", "db-cluster-snapshot-available", "--db-cluster-snapshot-identifier", snapshot)

        created_sg = aws_json("ec2", "create-security-group", "--group-name", restored_cluster,
                              "--description", "Autobot qualification restore quarantine", "--vpc-id", vpc_id,
                              "--tag-specifications", f"ResourceType=security-group,Tags=[{{Key=autobot.io/qualification,Value={RUN_ID}}}]")
        security_group = created_sg["GroupId"]
        aws("rds", "restore-db-cluster-from-snapshot",
            "--db-cluster-identifier", restored_cluster,
            "--snapshot-identifier", snapshot,
            "--engine", "aurora-postgresql", "--engine-version", engine_version,
            "--db-subnet-group-name", subnet_group,
            "--vpc-security-group-ids", security_group,
            "--kms-key-id", kms_key,
            "--serverless-v2-scaling-configuration", "MinCapacity=0,MaxCapacity=8,SecondsUntilAutoPause=300",
            "--tags", f"Key=autobot.io/qualification,Value={RUN_ID}")
        aws("rds", "wait", "db-cluster-available", "--db-cluster-identifier", restored_cluster)
        aws("rds", "create-db-instance", "--db-instance-identifier", restored_instance,
            "--db-cluster-identifier", restored_cluster, "--engine", "aurora-postgresql",
            "--db-instance-class", "db.serverless", "--no-publicly-accessible",
            "--tags", f"Key=autobot.io/qualification,Value={RUN_ID}")
        aws("rds", "wait", "db-instance-available", "--db-instance-identifier", restored_instance)
        restored = aws_json("rds", "describe-db-clusters", "--db-cluster-identifier", restored_cluster)["DBClusters"][0]
        restored_node = aws_json("rds", "describe-db-instances", "--db-instance-identifier", restored_instance)["DBInstances"][0]
        restored_endpoint = restored["Endpoint"]

        aws("ec2", "authorize-security-group-ingress", "--group-id", security_group,
            "--protocol", "tcp", "--port", "5432", "--source-group", node_sg)
        ingress_open = True
        recovered = database_state(restored_endpoint)
        aws("ec2", "revoke-security-group-ingress", "--group-id", security_group,
            "--protocol", "tcp", "--port", "5432", "--source-group", node_sg)
        ingress_open = False

        report["database"] = {"source": source, "restored": recovered, "restored_public": restored_node["PubliclyAccessible"]}
        report["assertions"]["T16_aurora_snapshot_restores_exact_application_state"] = (
            source == recovered and restored_node["PubliclyAccessible"] is False
        )
        report["assertions"]["T16_evidence_object_is_versioned_and_kms_encrypted"] = (
            bool(object_version) and head.get("ServerSideEncryption") == "aws:kms" and head.get("SSEKMSKeyId") == kms_key
        )

        aws("s3api", "delete-object", "--bucket", bucket, "--key", object_key, "--version-id", object_version)
        deleted = aws("s3api", "head-object", "--bucket", bucket, "--key", object_key,
                      "--version-id", object_version, check=False)
        report["assertions"]["T16_deleted_object_version_is_unreadable"] = deleted.returncode != 0
        object_version = None
        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
        return 0 if report["result"] == "passed" else 1
    except Exception as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        return 1
    finally:
        if ingress_open and security_group and node_sg:
            aws("ec2", "revoke-security-group-ingress", "--group-id", security_group,
                "--protocol", "tcp", "--port", "5432", "--source-group", node_sg, check=False)
        aws("rds", "delete-db-instance", "--db-instance-identifier", restored_instance,
            "--skip-final-snapshot", check=False)
        aws("rds", "wait", "db-instance-deleted", "--db-instance-identifier", restored_instance, check=False)
        aws("rds", "delete-db-cluster", "--db-cluster-identifier", restored_cluster,
            "--skip-final-snapshot", check=False)
        aws("rds", "wait", "db-cluster-deleted", "--db-cluster-identifier", restored_cluster, check=False)
        aws("rds", "delete-db-cluster-snapshot", "--db-cluster-snapshot-identifier", snapshot, check=False)
        if object_version:
            aws("s3api", "delete-object", "--bucket", bucket, "--key", object_key,
                "--version-id", object_version, check=False)
        if security_group:
            aws("ec2", "delete-security-group", "--group-id", security_group, check=False)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = EVIDENCE / "recovery.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result": report.get("result"), "evidence": str(path), "assertions": report["assertions"]}, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
