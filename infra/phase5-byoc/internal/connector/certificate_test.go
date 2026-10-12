package connector

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateInstallBindsLocalKeySPIFFEAndClientUsage(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "connector.key")
	identity := "spiffe://customer.example/autobot/connector-a"
	csrPEM, err := EnsureTLSKeyAndCSR(keyPath, identity)
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || len(csr.URIs) != 1 || csr.URIs[0].String() != identity {
		t.Fatal("generated CSR did not retain the exact connector identity")
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Autobot BYOC test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	identityURL, _ := url.Parse(identity)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{identityURL}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, csr.PublicKey, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	response := CertificateResponse{
		ClientCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		CACertificate:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
	}
	certPath := filepath.Join(directory, "connector.crt")
	caPath := filepath.Join(directory, "ca.crt")
	if err := InstallCertificate(certPath, caPath, keyPath, identity, response); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	}
	if err := InstallCertificate(certPath, caPath, keyPath, "spiffe://customer.example/autobot/connector-b", response); err == nil {
		t.Fatal("certificate was installed for a substituted SPIFFE identity")
	}
}
