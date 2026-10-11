package connector

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestPythonCanonicalSignatureFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/fixtures/byoc-connector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKey       string         `json:"public_key"`
		Proof           map[string]any `json:"proof"`
		ProofSignature  string         `json:"proof_signature"`
		Health          map[string]any `json:"health"`
		HealthSignature string         `json:"health_signature"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]struct {
		payload   map[string]any
		signature string
	}{
		"proof":  {fixture.Proof, fixture.ProofSignature},
		"health": {fixture.Health, fixture.HealthSignature},
	} {
		canonical, err := Canonical(value.payload)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.URLEncoding.DecodeString(value.signature)
		if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
			t.Fatalf("%s signature fixture did not verify", name)
		}
	}
}

func fixture(t *testing.T) (*Authority, Binding, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	managementPublic, managementPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{
		TenantID: "tenant-a", DeploymentID: "deployment-a", AccountID: "111111111111",
		Incarnation:     "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ConnectorSPIFFE: "spiffe://customer.example/vigil/connector-a", PolicyDigest: repeat("a", 64),
		ManagementPublicKey: base64.RawURLEncoding.EncodeToString(managementPublic),
	}
	authority, err := New(t.TempDir()+"/authority.json", binding, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return authority, binding, publicKey, privateKey, managementPrivate
}

func commandFor(binding Binding, now time.Time) Command {
	return Command{
		SchemaVersion: 1, CommandID: "command-1", Sequence: 1,
		TenantID: binding.TenantID, DeploymentID: binding.DeploymentID, AccountID: binding.AccountID,
		Incarnation: binding.Incarnation, Action: "release.install", ActionDigest: repeat("b", 64),
		ReleaseDigest: repeat("c", 64), PolicyDigest: binding.PolicyDigest, TrustVersion: 1, RevocationEpoch: 1,
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		CentralLeaseExpiry: now.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
}

func signed(t *testing.T, command Command, privateKey ed25519.PrivateKey) string {
	t.Helper()
	raw, err := Canonical(command)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, raw))
}

func TestApprovedCommandIsPinnedIdempotentAndBound(t *testing.T) {
	authority, binding, _, _, managementPrivate := fixture(t)
	now := time.Now().UTC()
	command := commandFor(binding, now)
	approval := Approval{
		ApprovalID: "approval-1", Action: command.Action, ActionDigest: command.ActionDigest,
		Approver: "customer-approver", Requester: "platform-requester", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if err := authority.AddApproval(approval, now); err != nil {
		t.Fatal(err)
	}
	signature := signed(t, command, managementPrivate)
	if err := authority.Apply(command, signature, approval.ApprovalID, now); err != nil {
		t.Fatal(err)
	}
	if authority.State().InstalledRelease != command.ReleaseDigest {
		t.Fatal("approved release was not pinned")
	}
	if err := authority.Apply(command, signature, approval.ApprovalID, now); err != nil {
		t.Fatalf("identical retry was not idempotent: %v", err)
	}
	altered := command
	altered.ReleaseDigest = repeat("d", 64)
	if err := authority.Apply(altered, signed(t, altered, managementPrivate), approval.ApprovalID, now); err == nil {
		t.Fatal("conflicting command replay was accepted")
	}
}

func TestForeignExpiredAndUnapprovedCommandsFailClosed(t *testing.T) {
	authority, binding, _, _, managementPrivate := fixture(t)
	now := time.Now().UTC()
	for name, mutate := range map[string]func(*Command){
		"foreign tenant": func(c *Command) { c.TenantID = "tenant-b" },
		"expired lease":  func(c *Command) { c.CentralLeaseExpiry = now.Add(-time.Second).Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			command := commandFor(binding, now)
			mutate(&command)
			if err := authority.Apply(command, signed(t, command, managementPrivate), "", now); err == nil {
				t.Fatal("unauthorized command was accepted")
			}
		})
	}
	command := commandFor(binding, now)
	if err := authority.Apply(command, signed(t, command, managementPrivate), "missing", now); err == nil {
		t.Fatal("approval-required command was accepted without approval")
	}
}

func TestEmergencyRevocationAndBoundedOutboxSurviveRestart(t *testing.T) {
	authority, binding, publicKey, privateKey, managementPrivate := fixture(t)
	now := time.Now().UTC()
	for index := 0; index < MaxOutbox+5; index++ {
		if err := authority.QueueHealth("heartbeat", HealthPayload{Status: "healthy"}, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(authority.State().Outbox) != MaxOutbox || authority.State().DroppedHealth != 5 {
		t.Fatal("health outbox was not bounded")
	}
	if authority.State().Outbox[0].Sequence != 1 || authority.State().Outbox[MaxOutbox-1].Sequence != MaxOutbox || authority.State().Outbox[MaxOutbox-1].EventKind != "gap" || authority.State().NextHealthSequence != MaxOutbox+1 {
		t.Fatal("health overflow did not preserve a contiguous prefix with a gap marker")
	}
	if err := authority.EmergencyRevoke(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(authority.path, binding, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State().ManagementEnabled || reloaded.State().RevocationEpoch != 2 {
		t.Fatal("local revocation did not survive restart")
	}
	command := commandFor(binding, now)
	if err := reloaded.Apply(command, signed(t, command, managementPrivate), "", now); err == nil {
		t.Fatal("centrally signed command bypassed local revocation")
	}
}

func TestAlteredLocalAuthorityStateIsRejected(t *testing.T) {
	authority, binding, publicKey, privateKey, _ := fixture(t)
	raw, err := os.ReadFile(authority.path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	state := envelope["state"].(map[string]any)
	state["management_enabled"] = false
	altered, _ := json.Marshal(envelope)
	if err := os.WriteFile(authority.path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(authority.path, binding, publicKey, privateKey); err == nil {
		t.Fatal("altered local revocation state was accepted")
	}
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
