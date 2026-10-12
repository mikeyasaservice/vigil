package connector

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	SchemaVersion = 1
	MaxOutbox     = 128
)

type Binding struct {
	TenantID            string `json:"tenant_id"`
	DeploymentID        string `json:"deployment_id"`
	AccountID           string `json:"account_id"`
	Incarnation         string `json:"incarnation"`
	ConnectorSPIFFE     string `json:"connector_spiffe_id"`
	PolicyDigest        string `json:"local_policy_digest"`
	ManagementPublicKey string `json:"management_public_key"`
}

type Approval struct {
	ApprovalID   string `json:"approval_id"`
	Action       string `json:"action"`
	ActionDigest string `json:"action_digest"`
	Approver     string `json:"approver"`
	Requester    string `json:"requester"`
	ExpiresAt    string `json:"expires_at"`
}

type Command struct {
	SchemaVersion      int    `json:"schema_version"`
	CommandID          string `json:"command_id"`
	Sequence           uint64 `json:"sequence"`
	TenantID           string `json:"tenant_id"`
	DeploymentID       string `json:"deployment_id"`
	AccountID          string `json:"account_id"`
	Incarnation        string `json:"incarnation"`
	Action             string `json:"action"`
	ActionDigest       string `json:"action_digest"`
	ReleaseDigest      string `json:"release_digest,omitempty"`
	PolicyDigest       string `json:"policy_digest"`
	TrustVersion       uint64 `json:"trust_version"`
	RevocationEpoch    uint64 `json:"revocation_epoch"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	CentralLeaseExpiry string `json:"central_lease_expires_at"`
}

type HealthPayload struct {
	Status                  string                 `json:"status"`
	ObservedGeneration      uint64                 `json:"observed_generation"`
	ReleaseDigest           *string                `json:"release_digest"`
	BacklogCount            uint64                 `json:"backlog_count"`
	DroppedCount            uint64                 `json:"dropped_count"`
	StorageWatermarkPercent uint64                 `json:"storage_watermark_percent"`
	DSPyEvaluation          *DSPyEvaluationReceipt `json:"dspy_evaluation,omitempty"`
}

type DSPyEvaluationReceipt struct {
	SchemaVersion        string             `json:"schema_version"`
	TenantID             string             `json:"tenant_id"`
	DeploymentID         string             `json:"deployment_id"`
	EvaluationID         string             `json:"evaluation_id"`
	DatasetDigest        string             `json:"dataset_digest"`
	ProgramDigest        string             `json:"program_digest"`
	ModelConfigDigest    string             `json:"model_config_digest"`
	MetricContractDigest string             `json:"metric_contract_digest"`
	SplitName            string             `json:"split_name"`
	Metrics              map[string]float64 `json:"metrics"`
	Passed               bool               `json:"passed"`
	CompletedAt          string             `json:"completed_at"`
	Signature            string             `json:"signature"`
}

type EnrollmentProof struct {
	SchemaVersion     int    `json:"schema_version"`
	EnrollmentID      string `json:"enrollment_id"`
	TenantID          string `json:"tenant_id"`
	DeploymentID      string `json:"deployment_id"`
	AccountID         string `json:"account_id"`
	ConnectorSPIFFE   string `json:"connector_spiffe_id"`
	LocalPolicyDigest string `json:"local_policy_digest"`
}

type HealthEvent struct {
	Incarnation     string        `json:"incarnation"`
	Sequence        uint64        `json:"sequence"`
	EventKind       string        `json:"event_kind"`
	OccurredAt      string        `json:"occurred_at"`
	RevocationEpoch uint64        `json:"revocation_epoch"`
	Payload         HealthPayload `json:"payload"`
	Signature       string        `json:"signature,omitempty"`
}

type State struct {
	SchemaVersion       int                 `json:"schema_version"`
	Binding             Binding             `json:"binding"`
	TrustVersion        uint64              `json:"trust_version"`
	RevocationEpoch     uint64              `json:"revocation_epoch"`
	ManagementEnabled   bool                `json:"management_enabled"`
	LastCommandSequence uint64              `json:"last_command_sequence"`
	NextHealthSequence  uint64              `json:"next_health_sequence"`
	CentralLeaseExpiry  string              `json:"central_lease_expires_at"`
	InstalledRelease    string              `json:"installed_release_digest"`
	Approvals           map[string]Approval `json:"approvals"`
	AppliedCommands     map[string]string   `json:"applied_commands"`
	Outbox              []HealthEvent       `json:"health_outbox"`
	DroppedHealth       uint64              `json:"dropped_health"`
}

type stateEnvelope struct {
	State     State  `json:"state"`
	Signature string `json:"signature"`
}

type Authority struct {
	path       string
	state      State
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func Canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func Digest(value any) (string, error) {
	raw, err := Canonical(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func New(path string, binding Binding, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Authority, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("connector signing key is invalid")
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, errors.New("connector signing key pair does not match")
	}
	managementKey, keyErr := base64.RawURLEncoding.DecodeString(binding.ManagementPublicKey)
	if binding.TenantID == "" || binding.DeploymentID == "" || binding.AccountID == "" || binding.Incarnation == "" || binding.ConnectorSPIFFE == "" || len(binding.PolicyDigest) != 64 || keyErr != nil || len(managementKey) != ed25519.PublicKeySize {
		return nil, errors.New("connector binding is incomplete")
	}
	authority := &Authority{path: path, publicKey: publicKey, privateKey: privateKey, state: State{
		SchemaVersion: SchemaVersion, Binding: binding, TrustVersion: 1, RevocationEpoch: 1,
		ManagementEnabled: true, NextHealthSequence: 1, Approvals: map[string]Approval{}, AppliedCommands: map[string]string{},
	}}
	if err := authority.save(); err != nil {
		return nil, err
	}
	return authority, nil
}

func Load(path string, expected Binding, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Authority, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("local authority state permissions are invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope stateEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode local authority: %w", err)
	}
	stateRaw, err := Canonical(envelope.State)
	if err != nil || !ed25519.Verify(publicKey, stateRaw, decodeSignature(envelope.Signature)) {
		return nil, errors.New("local authority state signature is invalid")
	}
	state := envelope.State
	if state.SchemaVersion != SchemaVersion || state.Binding != expected || state.TrustVersion == 0 || state.RevocationEpoch == 0 || state.NextHealthSequence == 0 {
		return nil, errors.New("local authority does not match the trusted customer binding")
	}
	if state.Approvals == nil || state.AppliedCommands == nil || len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("local authority state is incomplete")
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, errors.New("connector signing key pair does not match")
	}
	return &Authority{path: path, state: state, publicKey: publicKey, privateKey: privateKey}, nil
}

func (a *Authority) State() State { return a.state }

func (a *Authority) OldestHealth() (HealthEvent, bool) {
	if len(a.state.Outbox) == 0 {
		return HealthEvent{}, false
	}
	return a.state.Outbox[0], true
}

func (a *Authority) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(a.publicKey)
}

func (a *Authority) SignEnrollment(enrollmentID string) (EnrollmentProof, string, error) {
	proof := EnrollmentProof{
		SchemaVersion: 1, EnrollmentID: enrollmentID, TenantID: a.state.Binding.TenantID,
		DeploymentID: a.state.Binding.DeploymentID, AccountID: a.state.Binding.AccountID,
		ConnectorSPIFFE: a.state.Binding.ConnectorSPIFFE, LocalPolicyDigest: a.state.Binding.PolicyDigest,
	}
	raw, err := Canonical(proof)
	if err != nil {
		return proof, "", err
	}
	return proof, base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.privateKey, raw)), nil
}

func (a *Authority) AddApproval(approval Approval, now time.Time) error {
	expires, err := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	if err != nil || !expires.After(now) || expires.After(now.Add(24*time.Hour)) || approval.Approver == approval.Requester || approval.ActionDigest == "" {
		return errors.New("customer approval is invalid")
	}
	a.state.Approvals[approval.ApprovalID] = approval
	return a.save()
}

func (a *Authority) Apply(command Command, signature string, approvalID string, now time.Time) error {
	managementKey, err := base64.RawURLEncoding.DecodeString(a.state.Binding.ManagementPublicKey)
	if err != nil || len(managementKey) != ed25519.PublicKeySize {
		return errors.New("management command trust is unavailable")
	}
	canonical, err := Canonical(command)
	if err != nil || !ed25519.Verify(managementKey, canonical, decodeSignature(signature)) {
		return errors.New("management command signature is invalid")
	}
	digest, err := Digest(command)
	if err != nil {
		return err
	}
	if held, ok := a.state.AppliedCommands[command.CommandID]; ok {
		if held != digest {
			return errors.New("command ID was reused with different content")
		}
		return nil
	}
	if !a.state.ManagementEnabled {
		return errors.New("management is locally revoked")
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, command.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, command.ExpiresAt)
	lease, leaseErr := time.Parse(time.RFC3339Nano, command.CentralLeaseExpiry)
	if issueErr != nil || expiryErr != nil || leaseErr != nil || issued.After(now.Add(time.Minute)) || !expires.After(now) || expires.Sub(issued) > 10*time.Minute || !lease.After(now) {
		return errors.New("management command authority is expired")
	}
	b := a.state.Binding
	if command.SchemaVersion != SchemaVersion || command.TenantID != b.TenantID || command.DeploymentID != b.DeploymentID || command.AccountID != b.AccountID || command.Incarnation != b.Incarnation || command.PolicyDigest != b.PolicyDigest {
		return errors.New("management command does not match the customer binding")
	}
	if command.Sequence != a.state.LastCommandSequence+1 || command.TrustVersion != a.state.TrustVersion || command.RevocationEpoch != a.state.RevocationEpoch {
		return errors.New("management command generation is stale")
	}
	switch command.Action {
	case "release.install", "policy.install", "support.open":
		approval, ok := a.state.Approvals[approvalID]
		approvalExpiry, parseErr := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
		if !ok || parseErr != nil || !approvalExpiry.After(now) || approval.Action != command.Action || approval.ActionDigest != command.ActionDigest {
			return errors.New("customer approval does not authorize the command")
		}
		delete(a.state.Approvals, approvalID)
	case "management.revoke":
		a.state.ManagementEnabled = false
		a.state.RevocationEpoch++
	default:
		return errors.New("management command action is not allowed")
	}
	if command.Action == "release.install" {
		if len(command.ReleaseDigest) != 64 {
			return errors.New("release command has no immutable artifact digest")
		}
		a.state.InstalledRelease = command.ReleaseDigest
	}
	a.state.LastCommandSequence = command.Sequence
	a.state.CentralLeaseExpiry = command.CentralLeaseExpiry
	a.state.AppliedCommands[command.CommandID] = digest
	return a.save()
}

func (a *Authority) EmergencyRevoke() error {
	a.state.ManagementEnabled = false
	a.state.RevocationEpoch++
	a.state.CentralLeaseExpiry = ""
	return a.save()
}

func (a *Authority) QueueHealth(kind string, payload HealthPayload, now time.Time) error {
	allowed := map[string]bool{"heartbeat": true, "release": true, "capacity": true, "gap": true, "revocation": true, "dspy_evaluation": true}
	if !allowed[kind] || payload.StorageWatermarkPercent > 100 {
		return errors.New("health event is outside the allowlist")
	}
	if kind == "dspy_evaluation" {
		receipt := payload.DSPyEvaluation
		validSplit := receipt != nil && (receipt.SplitName == "development" || receipt.SplitName == "holdout" || receipt.SplitName == "safety")
		if !validSplit || receipt.SchemaVersion != "autobot.dspy.evaluation-receipt/v1" ||
			receipt.TenantID != a.state.Binding.TenantID || receipt.DeploymentID != a.state.Binding.DeploymentID ||
			len(receipt.EvaluationID) != 36 || len(receipt.DatasetDigest) != 71 || len(receipt.ProgramDigest) != 71 ||
			len(receipt.ModelConfigDigest) != 71 || len(receipt.MetricContractDigest) != 71 || len(receipt.Signature) < 32 {
			return errors.New("DSPy evaluation receipt is outside the customer binding")
		}
		if _, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt); err != nil || len(receipt.Metrics) == 0 {
			return errors.New("DSPy evaluation receipt is incomplete")
		}
	} else if payload.DSPyEvaluation != nil {
		return errors.New("DSPy evaluation data is not allowed on this health event")
	}
	if len(a.state.Outbox) >= MaxOutbox {
		a.state.DroppedHealth++
		payload.Status = "degraded"
		payload.DroppedCount = a.state.DroppedHealth
		payload.DSPyEvaluation = nil
		last := len(a.state.Outbox) - 1
		event := HealthEvent{
			Incarnation: a.state.Binding.Incarnation, Sequence: a.state.Outbox[last].Sequence,
			EventKind: "gap", OccurredAt: now.UTC().Format(time.RFC3339Nano),
			RevocationEpoch: a.state.RevocationEpoch, Payload: payload,
		}
		canonical, err := Canonical(event)
		if err != nil {
			return err
		}
		event.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.privateKey, canonical))
		a.state.Outbox[last] = event
		return a.save()
	}
	payload.DroppedCount = a.state.DroppedHealth
	event := HealthEvent{
		Incarnation: a.state.Binding.Incarnation, Sequence: a.state.NextHealthSequence,
		EventKind: kind, OccurredAt: now.UTC().Format(time.RFC3339Nano),
		RevocationEpoch: a.state.RevocationEpoch, Payload: payload,
	}
	canonical, err := Canonical(event)
	if err != nil {
		return err
	}
	event.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.privateKey, canonical))
	a.state.Outbox = append(a.state.Outbox, event)
	a.state.NextHealthSequence++
	return a.save()
}

func (a *Authority) AckHealth(sequence uint64) error {
	if len(a.state.Outbox) == 0 || a.state.Outbox[0].Sequence != sequence {
		return errors.New("health acknowledgement is not for the oldest event")
	}
	a.state.Outbox = a.state.Outbox[1:]
	return a.save()
}

func (a *Authority) save() error {
	canonical, err := Canonical(a.state)
	if err != nil {
		return err
	}
	envelope := stateEnvelope{
		State: a.state, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.privateKey, canonical)),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	directory := filepath.Dir(a.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".authority-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, a.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func decodeSignature(value string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(value)
	return decoded
}
