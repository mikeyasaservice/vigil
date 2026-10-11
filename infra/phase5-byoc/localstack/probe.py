#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--outputs", type=Path, required=True)
    args = parser.parse_args()
    outputs = json.loads(args.outputs.read_text())
    assert outputs["accountId"] == "111111111111"
    assert outputs["customerOwnedState"] is True
    assert outputs["centralCredentialCopies"] == 0
    assert '"Resource":"*"' not in outputs["runtimePolicy"]
    session = boto3.Session(
        aws_access_key_id=outputs["accountId"],
        aws_secret_access_key="localstack-only",
        region_name="us-east-1",
    )
    config = Config(retries={"max_attempts": 2}, s3={"addressing_style": "path"})
    clients = {
        name: session.client(name, endpoint_url=args.endpoint, config=config)
        for name in ("s3", "sqs", "secretsmanager", "sts")
    }
    assert clients["sts"].get_caller_identity()["Account"] == outputs["accountId"]
    for bucket_key, canary in (("evidenceBucket", b"customer-evidence"), ("backupBucket", b"customer-backup")):
        bucket = outputs[bucket_key]
        clients["s3"].put_object(Bucket=bucket, Key="qualification/canary", Body=canary)
        assert clients["s3"].get_object(Bucket=bucket, Key="qualification/canary")["Body"].read() == canary
        assert clients["s3"].get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
        encryption = clients["s3"].get_bucket_encryption(Bucket=bucket)
        rule = encryption["ServerSideEncryptionConfiguration"]["Rules"][0]
        assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    clients["sqs"].send_message(QueueUrl=outputs["executionQueueUrl"], MessageBody="qualification")
    assert clients["sqs"].receive_message(QueueUrl=outputs["executionQueueUrl"], MaxNumberOfMessages=1)["Messages"]
    try:
        clients["secretsmanager"].get_secret_value(SecretId=outputs["integrationSecretArn"])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] in {"ResourceNotFoundException", "ResourceNotFound"}
    else:
        raise AssertionError("installer copied an integration credential into the reference secret")
    print("PASS: customer-owned LocalStack resources work, use KMS/versioning, and contain no central credential copy")


if __name__ == "__main__":
    main()
