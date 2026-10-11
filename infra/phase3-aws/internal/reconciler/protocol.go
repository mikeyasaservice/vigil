package reconciler

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"vigil-managed-dedicated-aws/internal/spec"
)

type Command struct {
	SchemaVersion    int             `json:"schema_version"`
	CommandID        string          `json:"command_id"`
	OperationID      string          `json:"operation_id"`
	Phase            string          `json:"phase"`
	TenantID         string          `json:"tenant_id"`
	DeploymentID     string          `json:"deployment_id"`
	ManifestDigest   string          `json:"manifest_digest"`
	BindingDigest    string          `json:"binding_digest"`
	PlanHash         *string         `json:"plan_hash"`
	FencingToken     int64           `json:"fencing_token"`
	TargetGeneration int64           `json:"target_generation"`
	Placement        json.RawMessage `json:"placement"`
	Releases         json.RawMessage `json:"releases"`
	IssuedAt         string          `json:"issued_at"`
	ExpiresAt        string          `json:"expires_at"`
}

type ClaimResponse struct {
	Command   json.RawMessage `json:"command"`
	Signature string          `json:"signature"`
	Manifest  json.RawMessage `json:"manifest"`
}

type Receipt struct {
	OperationID        string            `json:"operation_id"`
	CommandID          string            `json:"command_id"`
	DeploymentID       string            `json:"deployment_id"`
	TenantID           string            `json:"tenant_id"`
	FencingToken       int64             `json:"fencing_token"`
	ManifestDigest     string            `json:"manifest_digest"`
	PlanHash           string            `json:"plan_hash"`
	ObservedGeneration int64             `json:"observed_generation"`
	ResourceInventory  map[string]string `json:"resource_inventory"`
	Verification       map[string]any    `json:"verification_summary"`
	ProviderUpdateID   string            `json:"provider_update_id,omitempty"`
	CompletedAt        string            `json:"completed_at"`
	Signature          string            `json:"signature,omitempty"`
}

func decodeURLBase64(value string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(value + strings.Repeat("=", (4-len(value)%4)%4))
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeURLBase64(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("management command public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func VerifyClaim(response ClaimResponse, publicKey ed25519.PublicKey, operationID, phase string, now time.Time) (Command, string, error) {
	var command Command
	canonical, err := spec.Canonicalize(response.Command)
	if err != nil {
		return command, "", fmt.Errorf("canonicalize command: %w", err)
	}
	signature, err := decodeURLBase64(response.Signature)
	if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
		return command, "", fmt.Errorf("management command signature is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(response.Command)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return command, "", fmt.Errorf("decode command: %w", err)
	}
	if command.SchemaVersion != 1 || command.OperationID != operationID || command.Phase != phase {
		return command, "", fmt.Errorf("management command does not match the requested operation")
	}
	if decoded, err := hex.DecodeString(command.BindingDigest); err != nil || len(decoded) != sha256.Size {
		return command, "", fmt.Errorf("management command binding digest is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, command.IssuedAt)
	if err != nil {
		return command, "", fmt.Errorf("command issue time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, command.ExpiresAt)
	if err != nil || !expiresAt.After(now) || issuedAt.After(now.Add(time.Minute)) || expiresAt.Sub(issuedAt) > 10*time.Minute {
		return command, "", fmt.Errorf("management command is outside its validity window")
	}
	manifestDigest, err := spec.CanonicalDigest(response.Manifest)
	if err != nil || manifestDigest != command.ManifestDigest {
		return command, "", fmt.Errorf("manifest digest does not match the signed command")
	}
	return command, manifestDigest, nil
}

func FileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func SignReceipt(receipt *Receipt, privateKeyPath string) error {
	raw, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	decoded, err := decodeURLBase64(strings.TrimSpace(string(raw)))
	if err != nil || (len(decoded) != ed25519.SeedSize && len(decoded) != ed25519.PrivateKeySize) {
		return fmt.Errorf("receipt private key is invalid")
	}
	privateKey := ed25519.PrivateKey(decoded)
	if len(decoded) == ed25519.SeedSize {
		privateKey = ed25519.NewKeyFromSeed(decoded)
	}
	unsigned := *receipt
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	canonical, err := spec.Canonicalize(payload)
	if err != nil {
		return err
	}
	receipt.Signature = base64.URLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}
