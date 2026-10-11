package cell

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
)

var tenantID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

func ValidateLocalStackEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("localstack endpoint must be a plain loopback HTTP origin")
	}
	if parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		return fmt.Errorf("localstack endpoint must use a loopback host")
	}
	if parsed.Port() == "" {
		return fmt.Errorf("localstack endpoint must include an explicit port")
	}
	return nil
}

func ValidateTenantIDs(values []string) error {
	if len(values) < 2 {
		return fmt.Errorf("shared-cell qualification requires at least two tenants")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !tenantID.MatchString(value) || seen[value] {
			return fmt.Errorf("tenant IDs must be unique lowercase slugs")
		}
		seen[value] = true
	}
	return nil
}

func RuntimePolicy(bucketARN, queueARN, keyARN, meteringQueueARN string) (string, error) {
	document := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid": "TenantBucketList", "Effect": "Allow",
				"Action": []string{"s3:ListBucket", "s3:GetBucketLocation"}, "Resource": bucketARN,
			},
			{
				"Sid": "TenantObjects", "Effect": "Allow",
				"Action": []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, "Resource": bucketARN + "/*",
			},
			{
				"Sid": "TenantQueue", "Effect": "Allow",
				"Action": []string{"sqs:GetQueueAttributes", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:SendMessage"}, "Resource": queueARN,
			},
			{
				"Sid": "TenantKey", "Effect": "Allow",
				"Action": []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"}, "Resource": keyARN,
			},
			{
				"Sid": "SharedMeteringIngress", "Effect": "Allow",
				"Action": "sqs:SendMessage", "Resource": meteringQueueARN,
			},
		},
	}
	encoded, err := json.Marshal(document)
	return string(encoded), err
}

func Sorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
