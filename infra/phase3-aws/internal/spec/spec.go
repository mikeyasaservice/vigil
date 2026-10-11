package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var (
	localRef    = regexp.MustCompile(`^local:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	approvedRef = regexp.MustCompile(`^approved:sha256:[a-f0-9]{64}$`)
	accountID   = regexp.MustCompile(`^[0-9]{12}$`)
)

type Release struct {
	Version   string `json:"version"`
	DigestRef string `json:"digest_ref"`
}

type DSPyRelease struct {
	Release
	ProgramID      string `json:"program_id"`
	ApprovalRef    string `json:"approval_ref"`
	ModelConfigRef string `json:"model_config_ref"`
}

type Isolation struct {
	Application string `json:"application"`
	Execution   string `json:"execution"`
	Database    string `json:"database"`
	QueueCache  string `json:"queue_cache"`
}

type Storage struct {
	DatabaseRef        string `json:"database_ref"`
	ObjectStoreRef     string `json:"object_store_ref"`
	MemoryRef          string `json:"memory_ref"`
	QueueRef           string `json:"queue_ref"`
	KeyRef             string `json:"key_ref"`
	RetentionPolicyRef string `json:"retention_policy_ref"`
}

type Credentials struct {
	IntegrationSecretRefs []string `json:"integration_secret_refs"`
	WorkloadIdentityRef   string   `json:"workload_identity_ref"`
}

type Network struct {
	IngressPolicyRef    string `json:"ingress_policy_ref"`
	EgressPolicyRef     string `json:"egress_policy_ref"`
	ManagementTransport string `json:"management_transport"`
	ArtifactMirrorRef   string `json:"artifact_mirror_ref"`
}

type Operations struct {
	BudgetPolicyRef          string `json:"budget_policy_ref"`
	ExportPolicyRef          string `json:"export_policy_ref"`
	BackupPolicyRef          string `json:"backup_policy_ref"`
	RecoveryTargetsRef       string `json:"recovery_targets_ref"`
	MaintenancePolicyRef     string `json:"maintenance_policy_ref"`
	SupportPolicyRef         string `json:"support_policy_ref"`
	ApprovalRef              string `json:"approval_ref"`
	RollbackCompatibilityRef string `json:"rollback_compatibility_ref"`
}

type Manifest struct {
	ContractVersion    string `json:"contract_version"`
	TenantID           string `json:"tenant_id"`
	DeploymentID       string `json:"deployment_id"`
	Incarnation        string `json:"incarnation"`
	Generation         int64  `json:"generation"`
	ExpectedGeneration int64  `json:"expected_generation"`
	Mode               string `json:"mode"`
	Placement          struct {
		Adapter           string `json:"adapter"`
		AccountBindingRef string `json:"account_binding_ref"`
		Region            string `json:"region"`
		NetworkBindingRef string `json:"network_binding_ref"`
		StateBindingRef   string `json:"state_binding_ref"`
	} `json:"placement"`
	Releases struct {
		Application    Release     `json:"application"`
		Harness        Release     `json:"harness"`
		Infrastructure Release     `json:"infrastructure"`
		DatabaseSchema string      `json:"database_schema"`
		Policy         Release     `json:"policy"`
		DSPy           DSPyRelease `json:"dspy"`
	} `json:"releases"`
	Isolation   Isolation   `json:"isolation"`
	Storage     Storage     `json:"storage"`
	Credentials Credentials `json:"credentials"`
	Network     Network     `json:"network"`
	Operations  Operations  `json:"operations"`
}

type Binding struct {
	BindingRef                 string   `json:"binding_ref"`
	TenantID                   string   `json:"tenant_id"`
	DeploymentID               string   `json:"deployment_id"`
	AccountID                  string   `json:"account_id"`
	RoleARN                    string   `json:"role_arn"`
	ExternalID                 string   `json:"external_id"`
	Region                     string   `json:"region"`
	NetworkBindingRef          string   `json:"network_binding_ref"`
	StateBindingRef            string   `json:"state_binding_ref"`
	StateBackendURL            string   `json:"state_backend_url"`
	SecretsProvider            string   `json:"secrets_provider"`
	PulumiHome                 string   `json:"pulumi_home"`
	WorkspaceRoot              string   `json:"workspace_root"`
	ReceiptPrivateKeyPath      string   `json:"receipt_private_key_path"`
	InfrastructureSourcePath   string   `json:"infrastructure_source_path"`
	ReconcilerSPIFFEID         string   `json:"reconciler_spiffe_id"`
	ManagementBaseURL          string   `json:"management_base_url"`
	ManagementServerName       string   `json:"management_server_name"`
	ManagementCAPath           string   `json:"management_ca_path"`
	ManagementClientCertPath   string   `json:"management_client_cert_path"`
	ManagementClientKeyPath    string   `json:"management_client_key_path"`
	PermittedAvailabilityZones []string `json:"permitted_availability_zones"`
	VpcCIDR                    string   `json:"vpc_cidr"`
	PublicSubnetCIDRs          []string `json:"public_subnet_cidrs"`
	PrivateSubnetCIDRs         []string `json:"private_subnet_cidrs"`
	PublicIngressCIDRs         []string `json:"public_ingress_cidrs"`
}

func readStrict[T any](path string) (T, []byte, error) {
	var value T
	raw, err := os.ReadFile(path)
	if err != nil {
		return value, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, nil, err
	}
	if decoder.More() {
		return value, nil, fmt.Errorf("multiple JSON values are not allowed")
	}
	return value, raw, nil
}

func Load(manifestPath, bindingPath string) (Manifest, Binding, string, error) {
	manifest, manifestRaw, err := readStrict[Manifest](manifestPath)
	if err != nil {
		return manifest, Binding{}, "", fmt.Errorf("read manifest: %w", err)
	}
	binding, _, err := readStrict[Binding](bindingPath)
	if err != nil {
		return manifest, binding, "", fmt.Errorf("read binding: %w", err)
	}
	if err := Validate(manifest, binding); err != nil {
		return manifest, binding, "", err
	}
	digest, err := CanonicalDigest(manifestRaw)
	if err != nil {
		return manifest, binding, "", fmt.Errorf("canonicalize manifest: %w", err)
	}
	return manifest, binding, digest, nil
}

func CanonicalDigest(raw []byte) (string, error) {
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func Canonicalize(raw []byte) ([]byte, error) {
	return jsoncanonicalizer.Transform(raw)
}

func Validate(m Manifest, b Binding) error {
	if m.ContractVersion != "managed-soc/v1" || m.Mode != "managed-dedicated" || m.Placement.Adapter != "aws-kubernetes" {
		return fmt.Errorf("unsupported deployment contract")
	}
	if m.Generation != m.ExpectedGeneration+1 || m.Generation < 1 {
		return fmt.Errorf("generation must advance exactly once")
	}
	if !localRef.MatchString(m.Placement.AccountBindingRef) || !localRef.MatchString(m.Placement.NetworkBindingRef) || !localRef.MatchString(m.Placement.StateBindingRef) {
		return fmt.Errorf("placement references are not trusted local references")
	}
	if m.TenantID != b.TenantID || m.DeploymentID != b.DeploymentID ||
		m.Placement.AccountBindingRef != b.BindingRef || m.Placement.Region != b.Region ||
		m.Placement.NetworkBindingRef != b.NetworkBindingRef || m.Placement.StateBindingRef != b.StateBindingRef {
		return fmt.Errorf("manifest target does not match the trusted binding")
	}
	if !accountID.MatchString(b.AccountID) || b.RoleARN == "" || b.ExternalID == "" {
		return fmt.Errorf("trusted AWS binding is incomplete")
	}
	if b.StateBackendURL == "" || b.SecretsProvider == "" || b.PulumiHome == "" ||
		b.WorkspaceRoot == "" || b.ReceiptPrivateKeyPath == "" || b.InfrastructureSourcePath == "" ||
		!regexp.MustCompile(`^spiffe://[^[:space:]]+$`).MatchString(b.ReconcilerSPIFFEID) ||
		!regexp.MustCompile(`^https://[^[:space:]]+$`).MatchString(b.ManagementBaseURL) || b.ManagementServerName == "" ||
		b.ManagementCAPath == "" || b.ManagementClientCertPath == "" || b.ManagementClientKeyPath == "" {
		return fmt.Errorf("trusted runner binding is incomplete")
	}
	if len(b.PermittedAvailabilityZones) < 2 {
		return fmt.Errorf("at least two permitted availability zones are required")
	}
	if len(b.PublicIngressCIDRs) != 0 {
		return fmt.Errorf("public ingress is not implemented for this deployment profile")
	}
	vpc, err := netip.ParsePrefix(b.VpcCIDR)
	if err != nil || len(b.PublicSubnetCIDRs) != len(b.PermittedAvailabilityZones) ||
		len(b.PrivateSubnetCIDRs) != len(b.PermittedAvailabilityZones) {
		return fmt.Errorf("trusted network binding is incomplete")
	}
	prefixes := make([]netip.Prefix, 0, len(b.PublicSubnetCIDRs)+len(b.PrivateSubnetCIDRs))
	for _, value := range append(append([]string{}, b.PublicSubnetCIDRs...), b.PrivateSubnetCIDRs...) {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !vpc.Contains(prefix.Addr()) || prefix.Bits() < vpc.Bits() {
			return fmt.Errorf("trusted subnet is outside the bound VPC")
		}
		for _, held := range prefixes {
			if held.Contains(prefix.Addr()) || prefix.Contains(held.Addr()) {
				return fmt.Errorf("trusted subnets overlap")
			}
		}
		prefixes = append(prefixes, prefix)
	}
	if m.Isolation.Application != "dedicated-runtime" || m.Isolation.Execution != "dedicated-tenant-nodes" ||
		m.Isolation.Database != "dedicated-instance" || m.Isolation.QueueCache != "dedicated-instance" ||
		m.Network.ManagementTransport != "outbound-mtls-https" {
		return fmt.Errorf("manifest weakens the managed dedicated isolation profile")
	}
	refs := []string{
		m.Releases.Application.DigestRef, m.Releases.Harness.DigestRef,
		m.Releases.Infrastructure.DigestRef, m.Releases.Policy.DigestRef,
		m.Releases.DSPy.DigestRef, m.Operations.RollbackCompatibilityRef,
	}
	for _, ref := range refs {
		if !approvedRef.MatchString(ref) {
			return fmt.Errorf("release reference is not an approved digest")
		}
	}
	localRefs := []string{
		m.Releases.DSPy.ApprovalRef, m.Releases.DSPy.ModelConfigRef,
		m.Storage.DatabaseRef, m.Storage.ObjectStoreRef, m.Storage.MemoryRef, m.Storage.QueueRef,
		m.Storage.KeyRef, m.Storage.RetentionPolicyRef, m.Credentials.WorkloadIdentityRef,
		m.Network.IngressPolicyRef, m.Network.EgressPolicyRef, m.Network.ArtifactMirrorRef,
		m.Operations.BudgetPolicyRef, m.Operations.ExportPolicyRef, m.Operations.BackupPolicyRef,
		m.Operations.RecoveryTargetsRef, m.Operations.MaintenancePolicyRef,
		m.Operations.SupportPolicyRef, m.Operations.ApprovalRef,
	}
	localRefs = append(localRefs, m.Credentials.IntegrationSecretRefs...)
	for _, ref := range localRefs {
		if !localRef.MatchString(ref) {
			return fmt.Errorf("manifest contains an untrusted local reference")
		}
	}
	if len(m.Credentials.IntegrationSecretRefs) > 64 {
		return fmt.Errorf("manifest has too many integration secret references")
	}
	seenSecrets := map[string]struct{}{}
	for _, ref := range m.Credentials.IntegrationSecretRefs {
		if _, exists := seenSecrets[ref]; exists {
			return fmt.Errorf("integration secret references must be unique")
		}
		seenSecrets[ref] = struct{}{}
	}
	return nil
}
