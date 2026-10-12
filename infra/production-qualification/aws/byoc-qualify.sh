#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../../.." && pwd)"
source_dir="$repo_dir/infra/phase5-byoc"
work_root="${AUTOBOT_BYOC_QUALIFICATION_ROOT:-/tmp/autobot-byoc-qualification}"
profile="${AWS_PROFILE:-pulumi}"
region="${AWS_REGION:-us-east-1}"
account_id="${AUTOBOT_AWS_ACCOUNT_ID:?set AUTOBOT_AWS_ACCOUNT_ID to the authorized qualification account}"

mkdir -p "$work_root/pulumi-home" "$work_root/state" "$work_root/source" "$work_root/evidence"
chmod 700 "$work_root"
if [[ ! -s "$work_root/passphrase" ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(64))' >"$work_root/passphrase"
fi
export PULUMI_CONFIG_PASSPHRASE="$(cat "$work_root/passphrase")"
export PULUMI_HOME="$work_root/pulumi-home"
export PULUMI_BACKEND_URL="file://$work_root/state"
export AWS_PROFILE="$profile" AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true

prepare() {
  rsync -a --delete --exclude '.local-state' --exclude 'Pulumi.*.yaml' "$source_dir/" "$work_root/source/"
  pulumi --cwd "$work_root/source" login "$PULUMI_BACKEND_URL" >/dev/null
  pulumi --cwd "$work_root/source" stack select aws-qualification --create --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:executionProfile aws-qualification --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:accountId "$account_id" --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:platformAccountId "$account_id" --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:region "$region" --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:awsProfile "$profile" --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:tenantId tenant-byoc-qualification --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:deploymentId deployment-byoc-qualification --non-interactive
  pulumi --cwd "$work_root/source" config set vigil-byoc-aws:ownershipAcknowledgement same-account-dev-qualification --non-interactive
}

apply_stack() {
  prepare
  pulumi --cwd "$work_root/source" preview --diff --non-interactive --save-plan "$work_root/plan.json"
  pulumi --cwd "$work_root/source" up --yes --non-interactive --plan "$work_root/plan.json"
  pulumi --cwd "$work_root/source" stack output --json >"$work_root/outputs.json"
  chmod 600 "$work_root/outputs.json"
}

test_stack() {
  [[ -s "$work_root/outputs.json" ]] || { echo "BYOC qualification outputs are missing" >&2; return 1; }
  local bucket backup queue key secret object_version timestamp evidence_file
  bucket="$(jq -er .evidenceBucket "$work_root/outputs.json")"
  backup="$(jq -er .backupBucket "$work_root/outputs.json")"
  queue="$(jq -er .executionQueueUrl "$work_root/outputs.json")"
  key="$(jq -er .keyArn "$work_root/outputs.json")"
  secret="$(jq -er .integrationSecretArn "$work_root/outputs.json")"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  evidence_file="$work_root/evidence/$timestamp-byoc-aws.json"
  printf '%s' "autobot-byoc-qualification-canary" >"$work_root/canary.txt"
  object_version="$(aws s3api put-object --bucket "$bucket" --key qualification/canary.txt \
    --body "$work_root/canary.txt" --server-side-encryption aws:kms --ssekms-key-id "$key" \
    --query VersionId --output text)"
  aws sqs send-message --queue-url "$queue" --message-body '{"kind":"qualification","contains_customer_data":false}' >/dev/null
  jq -n \
    --arg timestamp "$timestamp" --arg account "$account_id" --arg profile aws-qualification \
    --arg bucket "$bucket" --arg backup "$backup" --arg queue "$queue" --arg key "$key" --arg secret "$secret" \
    --arg version "$object_version" \
    --argjson rotation "$(aws kms get-key-rotation-status --key-id "$key" --output json)" \
    --argjson encryption "$(aws s3api get-bucket-encryption --bucket "$bucket" --output json)" \
    --argjson versioning "$(aws s3api get-bucket-versioning --bucket "$bucket" --output json)" \
    --argjson queueAttributes "$(aws sqs get-queue-attributes --queue-url "$queue" --attribute-names KmsMasterKeyId VisibilityTimeout MessageRetentionPeriod --output json)" \
    --argjson secretMetadata "$(aws secretsmanager describe-secret --secret-id "$secret" --output json | jq 'del(.ARN,.CreatedDate,.LastChangedDate,.LastAccessedDate,.Tags)')" \
    '{timestamp:$timestamp,scope:"same-account development qualification; not customer-owned BYOC",account_id:$account,
      execution_profile:$profile,resources:{evidence_bucket:$bucket,backup_bucket:$backup,queue_url:$queue,key_arn:$key,secret_arn:$secret},
      checks:{kms_rotation_enabled:$rotation.KeyRotationEnabled,s3_kms_encryption:($encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm=="aws:kms"),
      s3_versioning_enabled:($versioning.Status=="Enabled"),queue_kms_bound:($queueAttributes.Attributes.KmsMasterKeyId==$key),
      secret_has_no_value:($secretMetadata|has("SecretString")|not),object_version_created:($version|length>0)},object_version:$version}' \
    >"$evidence_file"
  jq -e '.checks | to_entries | all(.value == true)' "$evidence_file" >/dev/null
  aws s3api delete-object --bucket "$bucket" --key qualification/canary.txt --version-id "$object_version" >/dev/null
  printf '%s\n' "$evidence_file"
}

destroy_stack() {
  prepare
  cp "$work_root/outputs.json" "$work_root/outputs.pre-offboard.json"
  chmod 600 "$work_root/outputs.pre-offboard.json"
  pulumi --cwd "$work_root/source" destroy --yes --non-interactive
  python3 "$script_dir/byoc-offboard-verify.py"
}

case "${1:-preview}" in
  preview) prepare; pulumi --cwd "$work_root/source" preview --diff --non-interactive ;;
  apply) apply_stack ;;
  test) test_stack ;;
  qualify) apply_stack; test_stack ;;
  offboard) destroy_stack ;;
  *) echo "usage: $0 [preview|apply|test|qualify|offboard]" >&2; exit 2 ;;
esac
