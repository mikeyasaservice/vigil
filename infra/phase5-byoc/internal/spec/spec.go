package spec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
)

var (
	slug      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	accountID = regexp.MustCompile(`^[0-9]{12}$`)
)

func Validate(endpoint, account, tenant, deployment, acknowledgement string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" {
		return fmt.Errorf("LocalStack endpoint must be an explicit loopback HTTP origin")
	}
	if parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		return fmt.Errorf("LocalStack endpoint must use a loopback host")
	}
	if !accountID.MatchString(account) || account == "000000000000" {
		return fmt.Errorf("customer account ID must be a non-platform 12 digit account")
	}
	if !slug.MatchString(tenant) || !slug.MatchString(deployment) {
		return fmt.Errorf("tenant and deployment IDs must be lowercase slugs")
	}
	if acknowledgement != "customer-owned-account" {
		return fmt.Errorf("customer ownership acknowledgement is required")
	}
	return nil
}

func RuntimePolicy(bucketARN, backupARN, queueARN, keyARN, secretARN string) (string, error) {
	document := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{"Sid": "EvidenceBucket", "Effect": "Allow", "Action": []string{"s3:ListBucket", "s3:GetBucketLocation"}, "Resource": bucketARN},
			{"Sid": "EvidenceObjects", "Effect": "Allow", "Action": []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, "Resource": bucketARN + "/*"},
			{"Sid": "BackupRead", "Effect": "Allow", "Action": []string{"s3:ListBucket", "s3:GetObject"}, "Resource": []string{backupARN, backupARN + "/*"}},
			{"Sid": "TenantQueue", "Effect": "Allow", "Action": []string{"sqs:GetQueueAttributes", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:SendMessage"}, "Resource": queueARN},
			{"Sid": "TenantKey", "Effect": "Allow", "Action": []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"}, "Resource": keyARN},
			{"Sid": "TenantSecrets", "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secretARN},
		},
	}
	raw, err := json.Marshal(document)
	return string(raw), err
}
