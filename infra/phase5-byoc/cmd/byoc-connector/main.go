package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vigil-byoc-aws/internal/connector"
)

func main() {
	action := flag.String("action", "status", "init, status, or revoke")
	statePath := flag.String("state", "", "customer-owned authority state file")
	keyPath := flag.String("key", "", "customer-owned Ed25519 private key file")
	bindingPath := flag.String("binding", "", "trusted customer binding JSON")
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
