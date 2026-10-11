package reconciler

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vigil-managed-dedicated-aws/internal/spec"
)

func signedClaim(t *testing.T, now time.Time) (ClaimResponse, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := json.RawMessage(`{"tenant_id":"tenant-a","note":"café"}`)
	digest, err := spec.CanonicalDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	command := map[string]any{
		"schema_version": 1, "command_id": "command-a", "operation_id": "operation-a", "phase": "plan",
		"tenant_id": "tenant-a", "deployment_id": "deployment-a", "manifest_digest": digest,
		"binding_digest": strings.Repeat("a", 64),
		"plan_hash":      nil, "fencing_token": 1, "target_generation": 1,
		"placement": map[string]any{}, "releases": map[string]any{},
		"issued_at":  now.Add(-time.Second).Format(time.RFC3339Nano),
		"expires_at": now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	commandRaw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := spec.Canonicalize(commandRaw)
	if err != nil {
		t.Fatal(err)
	}
	return ClaimResponse{
		Command: commandRaw, Manifest: manifest,
		Signature: base64.URLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}, publicKey
}

func TestVerifyClaimBindsSignatureManifestAndPhase(t *testing.T) {
	now := time.Now().UTC()
	claim, publicKey := signedClaim(t, now)
	if _, _, err := VerifyClaim(claim, publicKey, "operation-a", "plan", now); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}

	altered := claim
	altered.Manifest = json.RawMessage(`{"tenant_id":"tenant-b","note":"café"}`)
	if _, _, err := VerifyClaim(altered, publicKey, "operation-a", "plan", now); err == nil {
		t.Fatal("altered manifest was accepted")
	}
	if _, _, err := VerifyClaim(claim, publicKey, "operation-a", "apply", now); err == nil {
		t.Fatal("plan command was accepted for apply")
	}
	if _, _, err := VerifyClaim(claim, publicKey, "operation-a", "plan", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired command was accepted")
	}
}

func TestTreeDigestAndCopyRejectMutationAndSymlinks(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "Pulumi.yaml"), []byte("name: phase3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := TreeDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "Pulumi.yaml"), []byte("name: altered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := TreeDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("artifact mutation did not change the source digest")
	}
	if err := os.Symlink("Pulumi.yaml", filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := TreeDigest(source); err == nil {
		t.Fatal("symlink was accepted in the infrastructure artifact")
	}
}
