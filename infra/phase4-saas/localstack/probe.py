#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


REGION = "us-east-1"


def client(service: str, endpoint: str, access_key: str):
    options = {
        "service_name": service,
        "endpoint_url": endpoint,
        "region_name": REGION,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": "test",
    }
    if service == "s3":
        options["config"] = Config(s3={"addressing_style": "path"})
    return boto3.client(**options)


def account_isolated(operation) -> bool:
    try:
        operation()
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {
            "AccessDenied",
            "AccessDeniedException",
            "AuthorizationError",
            "NoSuchBucket",
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        }:
            raise AssertionError(f"cross-account probe failed for unexpected reason {code}") from exc
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--outputs", type=Path, required=True)
    args = parser.parse_args()
    outputs = json.loads(args.outputs.read_text())
    buckets = outputs["tenantBuckets"]
    queues = outputs["tenantQueues"]
    accounts = outputs["tenantAccounts"]
    policies = outputs["tenantRuntimePolicies"]
    metering_queue = outputs["meteringQueueUrl"]
    if outputs.get("dataPlaneSharing") != "disabled-until-iam-qualified":
        raise AssertionError("shared data-plane resources must remain disabled")
    expected = {"tenant-a", "tenant-b"}
    if set(buckets) != expected or set(queues) != expected or set(accounts) != expected or set(policies) != expected:
        raise AssertionError("Pulumi outputs do not contain the exact A/B resource bindings")
    for tenant, encoded in policies.items():
        foreign = "tenant-b" if tenant == "tenant-a" else "tenant-a"
        normalized = json.dumps(json.loads(encoded), sort_keys=True)
        if buckets[foreign] in normalized or '"Resource": "*"' in normalized:
            raise AssertionError(f"{tenant} runtime policy contains foreign or wildcard resources")

    tenant_clients = {
        tenant: (
            client("s3", args.endpoint, account),
            client("sqs", args.endpoint, account),
            client("sts", args.endpoint, account),
        )
        for tenant, account in accounts.items()
    }
    for tenant, (s3, sqs, sts) in tenant_clients.items():
        if sts.get_caller_identity()["Account"] != accounts[tenant]:
            raise AssertionError(f"{tenant} credentials resolved to the wrong account")
        if buckets[tenant] not in {item["Name"] for item in s3.list_buckets()["Buckets"]}:
            raise AssertionError(f"{tenant} bucket was not provisioned in its bound account")
        if queues[tenant] not in set(sqs.list_queues().get("QueueUrls", [])):
            raise AssertionError(f"{tenant} queue was not provisioned in its bound account")
        s3.put_object(Bucket=buckets[tenant], Key="qualification/canary.txt", Body=f"{tenant}-canary".encode())

    platform_sqs = client("sqs", args.endpoint, "test")
    if metering_queue not in set(platform_sqs.list_queues().get("QueueUrls", [])):
        raise AssertionError("shared metering queue was not provisioned in the platform account")

    def queue_count(tenant: str) -> int:
        response = tenant_clients[tenant][1].get_queue_attributes(
            QueueUrl=queues[tenant], AttributeNames=["ApproximateNumberOfMessages"]
        )
        return int(response["Attributes"].get("ApproximateNumberOfMessages", "0"))

    before = {tenant: queue_count(tenant) for tenant in expected}
    for tenant in sorted(expected):
        foreign = "tenant-b" if tenant == "tenant-a" else "tenant-a"
        s3, sqs, _ = tenant_clients[tenant]
        canary = f"{tenant}-canary"
        held = s3.get_object(Bucket=buckets[tenant], Key="qualification/canary.txt")["Body"].read().decode()
        if held != canary:
            raise AssertionError(f"{tenant} positive S3 control returned the wrong canary")
        sqs.send_message(QueueUrl=queues[tenant], MessageBody=json.dumps({"tenant_id": tenant, "kind": "positive"}))
        if not account_isolated(lambda: s3.get_object(Bucket=buckets[foreign], Key="qualification/canary.txt")):
            print(
                f"UNQUALIFIED: LocalStack allowed {tenant} to read {foreign}; "
                "shared data-plane storage remains disabled"
            )

    for tenant, bucket in buckets.items():
        keys = {item["Key"] for item in tenant_clients[tenant][0].list_objects_v2(Bucket=bucket).get("Contents", [])}
        if "qualification/foreign.txt" in keys:
            raise AssertionError(f"unauthorized write changed {tenant} state")
    after = {tenant: queue_count(tenant) for tenant in expected}
    for tenant in expected:
        if after[tenant] != before[tenant] + 1:
            raise AssertionError(f"{tenant} queue counter changed outside its positive control")
    print(
        "Phase 4 LocalStack control-plane fixture passed: A/B resource positives and shared metering inventory; "
        "data-plane sharing remains disabled"
    )


if __name__ == "__main__":
    main()
