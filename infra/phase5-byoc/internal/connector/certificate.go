package connector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func EnsureTLSKeyAndCSR(keyPath, spiffeID string) (string, error) {
	identity, err := url.Parse(spiffeID)
	if err != nil || identity.Scheme != "spiffe" || identity.Host == "" {
		return "", errors.New("connector SPIFFE identity is invalid")
	}
	var key *ecdsa.PrivateKey
	raw, readErr := os.ReadFile(keyPath)
	if readErr == nil {
		info, statErr := os.Lstat(keyPath)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return "", errors.New("connector TLS private key permissions are invalid")
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return "", errors.New("connector TLS private key is invalid")
		}
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return "", errors.New("connector TLS private key is invalid")
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() {
			return "", errors.New("connector TLS private key algorithm is invalid")
		}
	} else if os.IsNotExist(readErr) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		encoded, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			return "", marshalErr
		}
		if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
			return "", err
		}
	} else {
		return "", readErr
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{identity}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), nil
}

func InstallCertificate(certPath, caPath, keyPath, spiffeID string, response CertificateResponse) error {
	certificate, _ := pem.Decode([]byte(response.ClientCertificate))
	ca, _ := pem.Decode([]byte(response.CACertificate))
	if certificate == nil || certificate.Type != "CERTIFICATE" || ca == nil || ca.Type != "CERTIFICATE" {
		return errors.New("management returned an invalid certificate chain")
	}
	leaf, err := x509.ParseCertificate(certificate.Bytes)
	if err != nil || time.Until(leaf.NotAfter) <= 5*time.Minute {
		return errors.New("management returned an unusable connector certificate")
	}
	caCertificate, err := x509.ParseCertificate(ca.Bytes)
	if err != nil || leaf.CheckSignatureFrom(caCertificate) != nil {
		return errors.New("management returned an untrusted connector certificate")
	}
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return errors.New("connector TLS private key is unavailable")
	}
	keyBlock, _ := pem.Decode(keyRaw)
	if keyBlock == nil {
		return errors.New("connector TLS private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return errors.New("connector TLS private key is invalid")
	}
	wantedPublic, _ := x509.MarshalPKIXPublicKey(key.Public())
	heldPublic, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !bytes.Equal(wantedPublic, heldPublic) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffeID {
		return errors.New("connector certificate does not match its local key and SPIFFE binding")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return errors.New("connector certificate is not valid for client authentication")
	}
	if err := writeAtomic(certPath, []byte(response.ClientCertificate), 0o600); err != nil {
		return err
	}
	return writeAtomic(caPath, []byte(response.CACertificate), 0o600)
}

func CertificateNeedsRotation(certPath string, before time.Duration, now time.Time) bool {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	return err != nil || !certificate.NotAfter.After(now.Add(before))
}

func writeAtomic(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
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
	return os.Rename(name, path)
}
