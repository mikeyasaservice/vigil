package cell

import (
	"encoding/json"
	"testing"
)

func TestValidationRejectsRemoteEndpointAndDuplicateTenant(t *testing.T) {
	if ValidateLocalStackEndpoint("https://localstack.example:4566") == nil {
		t.Fatal("remote LocalStack endpoint accepted")
	}
	if ValidateLocalStackEndpoint("http://127.0.0.1:4568") != nil {
		t.Fatal("loopback LocalStack endpoint rejected")
	}
	if ValidateTenantIDs([]string{"tenant-a", "tenant-a"}) == nil {
		t.Fatal("duplicate tenant accepted")
	}
}

func TestRuntimePolicyContainsOnlyBoundResources(t *testing.T) {
	encoded, err := RuntimePolicy("arn:bucket:a", "arn:queue:a", "arn:key:a", "arn:metering")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(encoded), &document); err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || contains(encoded, "arn:bucket:b") || contains(encoded, "Resource\":\"*") {
		t.Fatalf("policy widened authority: %s", encoded)
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
