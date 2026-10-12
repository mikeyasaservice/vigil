package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"vigil-byoc-aws/internal/connector"
)

func main() {
	action := flag.String("action", "status", "init, enroll, rotate, run, status, or revoke")
	statePath := flag.String("state", "", "customer-owned authority state file")
	keyPath := flag.String("key", "", "customer-owned Ed25519 private key file")
	bindingPath := flag.String("binding", "", "trusted customer binding JSON")
	managementURL := flag.String("management-url", "", "outbound management HTTPS origin")
	serverName := flag.String("server-name", "", "management TLS server name")
	caPath := flag.String("ca", "", "management CA bundle")
	certPath := flag.String("cert", "", "connector or bootstrap client certificate")
	tlsKeyPath := flag.String("tls-key", "", "customer-owned connector TLS private key")
	enrollmentID := flag.String("enrollment-id", "", "one-use enrollment identifier")
	enrollmentToken := flag.String("enrollment-token", "", "one-use enrollment bearer")
	heartbeat := flag.Duration("heartbeat", time.Minute, "health heartbeat interval")
	flag.Parse()
	if *statePath == "" || *keyPath == "" || *bindingPath == "" {
		fmt.Fprintln(os.Stderr, "state, key, and binding are required")
		os.Exit(2)
	}
	var binding connector.Binding
	raw, err := os.ReadFile(*bindingPath)
	if err != nil || json.Unmarshal(raw, &binding) != nil {
		fmt.Fprintln(os.Stderr, "trusted customer binding is invalid")
		os.Exit(2)
	}
	if *action == "init" {
		publicKey, privateKey, keyErr := connector.GenerateKey()
		if keyErr != nil {
			fail(keyErr)
		}
		if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
			fail(err)
		}
		keyFile, err := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fail(err)
		}
		if _, err := keyFile.WriteString(base64.RawURLEncoding.EncodeToString(privateKey)); err != nil {
			keyFile.Close()
			fail(err)
		}
		if err := keyFile.Sync(); err != nil {
			keyFile.Close()
			fail(err)
		}
		if err := keyFile.Close(); err != nil {
			fail(err)
		}
		authority, createErr := connector.New(*statePath, binding, publicKey, privateKey)
		if createErr != nil {
			fail(createErr)
		}
		fmt.Println(authority.PublicKeyBase64())
		return
	}
	privateKey := loadKey(*keyPath)
	authority, err := connector.Load(*statePath, binding, privateKey.Public().(ed25519.PublicKey), privateKey)
	if err != nil {
		fail(err)
	}
	if *action == "revoke" {
		if err := authority.EmergencyRevoke(); err != nil {
			fail(err)
		}
	} else if *action == "enroll" || *action == "rotate" || *action == "run" {
		if *managementURL == "" || *serverName == "" || *caPath == "" || *certPath == "" || *tlsKeyPath == "" {
			fail(fmt.Errorf("management-url, server-name, ca, cert, and tls-key are required"))
		}
		client, clientErr := connector.NewClient(connector.TransportConfig{
			ManagementURL: *managementURL, ServerName: *serverName, SPIFFEID: binding.ConnectorSPIFFE,
			CAPath: *caPath, CertPath: *certPath, KeyPath: *tlsKeyPath,
		})
		if clientErr != nil {
			fail(clientErr)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		csr, csrErr := connector.EnsureTLSKeyAndCSR(*tlsKeyPath, binding.ConnectorSPIFFE)
		if csrErr != nil {
			fail(csrErr)
		}
		if *action == "enroll" {
			if *enrollmentID == "" || *enrollmentToken == "" {
				fail(fmt.Errorf("enrollment-id and enrollment-token are required"))
			}
			_, signature, signErr := authority.SignEnrollment(*enrollmentID)
			if signErr != nil {
				fail(signErr)
			}
			response, enrollErr := client.Enroll(ctx, connector.EnrollmentRequest{
				EnrollmentID: *enrollmentID, EnrollmentToken: *enrollmentToken,
				AccountID: binding.AccountID, LocalPolicyDigest: binding.PolicyDigest,
				ConnectorPublicKey: authority.PublicKeyBase64(), ProofSignature: signature,
				CertificateSigningRequest: csr,
			})
			if enrollErr != nil {
				fail(enrollErr)
			}
			if response.TenantID != binding.TenantID || response.DeploymentID != binding.DeploymentID || response.AccountID != binding.AccountID || response.ConnectorSPIFFEID != binding.ConnectorSPIFFE || !response.ManagementEnabled {
				fail(fmt.Errorf("enrollment response does not match the customer binding"))
			}
			if err := connector.InstallCertificate(*certPath, *caPath, *tlsKeyPath, binding.ConnectorSPIFFE, response.CertificateResponse); err != nil {
				fail(err)
			}
		} else if *action == "rotate" {
			response, rotateErr := client.RotateCertificate(ctx, binding.DeploymentID, csr)
			if rotateErr != nil {
				fail(rotateErr)
			}
			if err := connector.InstallCertificate(*certPath, *caPath, *tlsKeyPath, binding.ConnectorSPIFFE, response); err != nil {
				fail(err)
			}
		} else {
			err := connector.Run(ctx, authority, client, connector.DaemonConfig{
				HeartbeatInterval: *heartbeat, RetryMinimum: time.Second, RetryMaximum: time.Minute,
				RotateBefore: 6 * time.Hour, CertPath: *certPath, CAPath: *caPath, TLSKeyPath: *tlsKeyPath,
			})
			if err != nil && ctx.Err() == nil {
				fail(err)
			}
		}
	} else if *action != "status" {
		fail(fmt.Errorf("unsupported action %q", *action))
	}
	encoded, _ := json.Marshal(authority.State())
	fmt.Println(string(encoded))
}

func loadKey(path string) ed25519.PrivateKey {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		fail(fmt.Errorf("connector key permissions are invalid"))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("connector key is invalid"))
	}
	return ed25519.PrivateKey(decoded)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
