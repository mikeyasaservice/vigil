package spec

import (
	"strings"
	"testing"
)

func TestValidateRequiresExplicitCustomerOwnership(t *testing.T) {
	if err := Validate("http://127.0.0.1:4569", "111111111111", "tenant-a", "deployment-a", "customer-owned-account"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ endpoint, account, acknowledgement string }{
		{"https://localstack.example", "111111111111", "customer-owned-account"},
		{"http://127.0.0.1:4569", "000000000000", "customer-owned-account"},
		{"http://127.0.0.1:4569", "111111111111", ""},
	} {
		if err := Validate(test.endpoint, test.account, "tenant-a", "deployment-a", test.acknowledgement); err == nil {
			t.Fatal("invalid BYOC binding was accepted")
		}
	}
}

func TestRuntimePolicyHasNoWildcardOrManagementSecret(t *testing.T) {
	policy, err := RuntimePolicy("arn:bucket:evidence", "arn:bucket:backup", "arn:queue", "arn:key", "arn:secret:tenant")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(policy, `"Resource":"*"`) || strings.Contains(policy, "management") {
		t.Fatalf("policy expanded beyond customer-owned resources: %s", policy)
	}
}
