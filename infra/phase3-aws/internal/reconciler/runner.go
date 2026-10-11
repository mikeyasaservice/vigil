package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optpreview"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optup"

	"vigil-managed-dedicated-aws/internal/spec"
)

type Runner struct {
	Client         *Client
	BindingPath    string
	CommandKeyPath string
	OperationID    string
	Phase          string
}

func (r *Runner) Run(ctx context.Context) (command Command, runErr error) {
	claim, err := r.Client.Claim(ctx, r.OperationID, r.Phase)
	if err != nil {
		return command, err
	}
	publicKey, err := LoadPublicKey(r.CommandKeyPath)
	if err != nil {
		return command, fmt.Errorf("load command verifier: %w", err)
	}
	command, digest, err := VerifyClaim(claim, publicKey, r.OperationID, r.Phase, time.Now().UTC())
	if err != nil {
		return command, err
	}
	defer func() {
		if runErr != nil && command.FencingToken > 0 {
			detail := runErr.Error()
			if len(detail) > 4000 {
				detail = detail[:4000]
			}
			_ = r.Client.Fail(context.Background(), r.OperationID, command.CommandID, command.FencingToken, r.Phase, "reconcile_failed", detail)
		}
	}()

	var manifest spec.Manifest
	if err := json.Unmarshal(claim.Manifest, &manifest); err != nil {
		return command, fmt.Errorf("decode manifest: %w", err)
	}
	var binding spec.Binding
	bindingRaw, err := os.ReadFile(r.BindingPath)
	if err != nil {
		return command, fmt.Errorf("read trusted binding: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(bindingRaw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return command, fmt.Errorf("decode trusted binding: %w", err)
	}
	if err := spec.Validate(manifest, binding); err != nil {
		return command, err
	}
	bindingDigest, err := spec.CanonicalDigest(bindingRaw)
	if err != nil || bindingDigest != command.BindingDigest {
		return command, fmt.Errorf("trusted binding does not match the admitted binding digest")
	}
	if command.TenantID != manifest.TenantID || command.DeploymentID != manifest.DeploymentID ||
		command.TargetGeneration != manifest.Generation {
		return command, fmt.Errorf("signed command does not match the trusted deployment binding")
	}

	sourceDigest, err := TreeDigest(binding.InfrastructureSourcePath)
	if err != nil {
		return command, fmt.Errorf("digest infrastructure artifact: %w", err)
	}
	if "approved:sha256:"+sourceDigest != manifest.Releases.Infrastructure.DigestRef {
		return command, fmt.Errorf("infrastructure artifact does not match the approved manifest digest")
	}

	operationRoot := filepath.Join(binding.WorkspaceRoot, manifest.DeploymentID, r.OperationID)
	sourceRoot := filepath.Join(operationRoot, "source")
	manifestPath := filepath.Join(operationRoot, "manifest.json")
	planPath := filepath.Join(operationRoot, "update.plan")
	if err := os.MkdirAll(operationRoot, 0o700); err != nil {
		return command, err
	}
	if r.Phase == "plan" {
		if _, err := os.Stat(sourceRoot); os.IsNotExist(err) {
			if err := CopyTree(binding.InfrastructureSourcePath, sourceRoot); err != nil {
				return command, fmt.Errorf("stage infrastructure artifact: %w", err)
			}
		}
		if err := os.WriteFile(manifestPath, claim.Manifest, 0o600); err != nil {
			return command, err
		}
	} else if _, err := os.Stat(planPath); err != nil {
		return command, fmt.Errorf("approved plan is unavailable: %w", err)
	}

	loadedManifest, loadedBinding, loadedDigest, err := spec.Load(manifestPath, r.BindingPath)
	if err != nil {
		return command, err
	}
	if loadedDigest != digest || loadedManifest.DeploymentID != manifest.DeploymentID || loadedBinding.BindingRef != binding.BindingRef {
		return command, fmt.Errorf("staged operation inputs changed")
	}

	stack, err := auto.UpsertStackLocalSource(ctx, manifest.DeploymentID, sourceRoot,
		auto.PulumiHome(binding.PulumiHome),
		auto.SecretsProvider(binding.SecretsProvider),
		auto.EnvVars(map[string]string{"PULUMI_BACKEND_URL": binding.StateBackendURL}),
	)
	if err != nil {
		return command, fmt.Errorf("open isolated Pulumi stack: %w", err)
	}
	project := "vigil-managed-dedicated-aws"
	if err := stack.SetConfig(ctx, project+":manifestPath", auto.ConfigValue{Value: manifestPath}); err != nil {
		return command, err
	}
	if err := stack.SetConfig(ctx, project+":bindingPath", auto.ConfigValue{Value: r.BindingPath}); err != nil {
		return command, err
	}

	if r.Phase == "plan" {
		if _, err := stack.Preview(ctx, optpreview.Plan(planPath)); err != nil {
			return command, fmt.Errorf("Pulumi preview failed: %w", err)
		}
		planHash, err := FileDigest(planPath)
		if err != nil {
			return command, err
		}
		if err := r.Client.PlanReady(ctx, r.OperationID, command.CommandID, command.FencingToken, digest, planHash); err != nil {
			return command, err
		}
		return command, nil
	}

	if command.PlanHash == nil {
		return command, fmt.Errorf("apply command has no approved plan hash")
	}
	planHash, err := FileDigest(planPath)
	if err != nil || planHash != *command.PlanHash {
		return command, fmt.Errorf("local plan does not match the approved plan hash")
	}
	result, err := stack.Up(ctx, optup.Plan(planPath))
	if err != nil {
		return command, fmt.Errorf("Pulumi apply failed: %w", err)
	}
	inventory := map[string]string{}
	for name, output := range result.Outputs {
		if !output.Secret {
			inventory[name] = fmt.Sprint(output.Value)
		}
	}
	verification := map[string]any{"pulumi_result": result.Summary.Result, "output_count": len(inventory)}
	receipt := Receipt{
		OperationID: r.OperationID, CommandID: command.CommandID, DeploymentID: manifest.DeploymentID, TenantID: manifest.TenantID,
		FencingToken: command.FencingToken, ManifestDigest: digest, PlanHash: planHash,
		ObservedGeneration: manifest.Generation, ResourceInventory: inventory, Verification: verification,
		ProviderUpdateID: fmt.Sprintf("pulumi-update-%d", result.Summary.Version),
		CompletedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := SignReceipt(&receipt, binding.ReceiptPrivateKeyPath); err != nil {
		return command, err
	}
	if err := r.Client.Complete(ctx, r.OperationID, receipt); err != nil {
		return command, err
	}
	return command, nil
}

func TreeDigest(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".pulumi") {
			return filepath.SkipDir
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("infrastructure artifact contains symlink %s", relative)
		}
		if entry.Type().IsRegular() {
			paths = append(paths, relative)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, relative := range paths {
		hash.Write([]byte(filepath.ToSlash(relative)))
		hash.Write([]byte{0})
		file, err := os.Open(filepath.Join(root, relative))
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CopyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".pulumi") {
			return filepath.SkipDir
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported infrastructure artifact entry %s", relative)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputCloseErr := input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputCloseErr != nil {
			return inputCloseErr
		}
		return closeErr
	})
}
