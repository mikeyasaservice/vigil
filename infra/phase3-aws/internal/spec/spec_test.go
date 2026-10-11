package spec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalDigestMatchesSharedFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "contracts", "fixtures", "managed-canonicalization.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input  json.RawMessage `json:"input"`
		SHA256 string          `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	held, err := CanonicalDigest(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	if held != fixture.SHA256 {
		t.Fatalf("digest mismatch: got %s want %s", held, fixture.SHA256)
	}
}

func validManifestAndBinding() (Manifest, Binding) {
	digest := "approved:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var manifest Manifest
	manifest.ContractVersion = "managed-soc/v1"
	manifest.Mode = "managed-dedicated"
	manifest.TenantID = "tenant-a"
	manifest.DeploymentID = "deployment-a"
	manifest.Generation = 1
	manifest.ExpectedGeneration = 0
	manifest.Placement.Adapter = "aws-kubernetes"
	manifest.Placement.AccountBindingRef = "local:account-a"
	manifest.Placement.NetworkBindingRef = "local:network-a"
	manifest.Placement.StateBindingRef = "local:state-a"
	manifest.Placement.Region = "us-east-1"
	manifest.Releases.Application.DigestRef = digest
	manifest.Releases.Harness.DigestRef = digest
	manifest.Releases.Infrastructure.DigestRef = digest
	manifest.Releases.Policy.DigestRef = digest
	manifest.Releases.DSPy.DigestRef = digest
	manifest.Operations.RollbackCompatibilityRef = digest
	manifest.Releases.DSPy.ApprovalRef = "local:dspy-approval"
	manifest.Releases.DSPy.ModelConfigRef = "local:model-config"
	manifest.Isolation = Isolation{Application: "dedicated-runtime", Execution: "dedicated-tenant-nodes", Database: "dedicated-instance", QueueCache: "dedicated-instance"}
	manifest.Storage = Storage{DatabaseRef: "local:database", ObjectStoreRef: "local:objects", MemoryRef: "local:memory", QueueRef: "local:queue", KeyRef: "local:key", RetentionPolicyRef: "local:retention"}
	manifest.Credentials = Credentials{IntegrationSecretRefs: []string{"local:integration"}, WorkloadIdentityRef: "local:workload"}
	manifest.Network = Network{IngressPolicyRef: "local:ingress", EgressPolicyRef: "local:egress", ManagementTransport: "outbound-mtls-https", ArtifactMirrorRef: "local:mirror"}
	manifest.Operations.BudgetPolicyRef = "local:budget"
	manifest.Operations.ExportPolicyRef = "local:export"
	manifest.Operations.BackupPolicyRef = "local:backup"
	manifest.Operations.RecoveryTargetsRef = "local:recovery"
	manifest.Operations.MaintenancePolicyRef = "local:maintenance"
	manifest.Operations.SupportPolicyRef = "local:support"
	manifest.Operations.ApprovalRef = "local:approval"
	binding := Binding{
		BindingRef: "local:account-a", TenantID: "tenant-a", DeploymentID: "deployment-a",
		AccountID: "111111111111", RoleARN: "arn:aws:iam::111111111111:role/VigilProvisioner",
		ExternalID: "external-a", Region: "us-east-1", NetworkBindingRef: "local:network-a",
		StateBindingRef: "local:state-a", StateBackendURL: "s3://vigil-pulumi-state-a",
		SecretsProvider: "awskms://alias/vigil-pulumi-a", PulumiHome: "/var/lib/vigil/pulumi/a",
		WorkspaceRoot: "/var/lib/vigil/workspaces/a", ReceiptPrivateKeyPath: "/var/run/secrets/vigil/receipt.key",
		InfrastructureSourcePath: "/opt/vigil/phase3-aws", ReconcilerSPIFFEID: "spiffe://vigil.io/management/reconciler-a",
		ManagementBaseURL: "https://management.vigil.internal", ManagementServerName: "management.vigil.internal",
		ManagementCAPath:         "/var/run/secrets/vigil/management-ca.pem",
		ManagementClientCertPath: "/var/run/secrets/vigil/tls.crt", ManagementClientKeyPath: "/var/run/secrets/vigil/tls.key",
		PermittedAvailabilityZones: []string{"us-east-1a", "us-east-1b"},
		VpcCIDR:                    "10.64.0.0/16", PublicSubnetCIDRs: []string{"10.64.0.0/24", "10.64.1.0/24"},
		PrivateSubnetCIDRs: []string{"10.64.16.0/20", "10.64.32.0/20"},
	}
	return manifest, binding
}

func TestValidateRejectsCrossTenantAndCrossAccountSubstitution(t *testing.T) {
	manifest, binding := validManifestAndBinding()
	if err := Validate(manifest, binding); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}

	foreign := binding
	foreign.TenantID = "tenant-b"
	if err := Validate(manifest, foreign); err == nil {
		t.Fatal("foreign tenant binding was accepted")
	}

	foreign = binding
	foreign.BindingRef = "local:account-b"
	foreign.AccountID = "222222222222"
	foreign.RoleARN = "arn:aws:iam::222222222222:role/VigilProvisioner"
	if err := Validate(manifest, foreign); err == nil {
		t.Fatal("foreign account binding was accepted")
	}
}

func TestValidateRejectsUnimplementedPublicIngress(t *testing.T) {
	manifest, binding := validManifestAndBinding()
	binding.PublicIngressCIDRs = []string{"203.0.113.0/24"}
	if err := Validate(manifest, binding); err == nil {
		t.Fatal("public ingress was accepted before the profile implements it")
	}
}
