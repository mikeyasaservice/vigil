package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"vigil-managed-dedicated-aws/internal/reconciler"
	"vigil-managed-dedicated-aws/internal/spec"
)

func main() {
	operationID := flag.String("operation", "", "management operation UUID")
	phase := flag.String("phase", "", "plan or apply")
	bindingPath := flag.String("binding", "", "trusted local binding JSON")
	commandKeyPath := flag.String("command-public-key", "", "management Ed25519 public key file")
	runnerID := flag.String("runner-id", "", "unique runner attempt identity")
	flag.Parse()
	if *operationID == "" || (*phase != "plan" && *phase != "apply") || *bindingPath == "" ||
		*commandKeyPath == "" || *runnerID == "" {
		fmt.Fprintln(os.Stderr, "operation, phase, binding, command-public-key, and runner-id are required")
		os.Exit(2)
	}
	bindingRaw, err := os.ReadFile(*bindingPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var binding spec.Binding
	decoder := json.NewDecoder(strings.NewReader(string(bindingRaw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	certificate, err := tls.LoadX509KeyPair(binding.ManagementClientCertPath, binding.ManagementClientKeyPath)
	if err != nil || len(certificate.Certificate) == 0 {
		fmt.Fprintln(os.Stderr, "reconciler client certificate is unavailable")
		os.Exit(2)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != binding.ReconcilerSPIFFEID {
		fmt.Fprintln(os.Stderr, "reconciler certificate does not match the trusted SPIFFE binding")
		os.Exit(2)
	}
	caPEM, err := os.ReadFile(binding.ManagementCAPath)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "management CA bundle is unavailable")
		os.Exit(2)
	}
	httpClient := &http.Client{
		Timeout: 15 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate},
			ServerName: binding.ManagementServerName,
		}},
	}
	client := &reconciler.Client{BaseURL: binding.ManagementBaseURL, RunnerID: *runnerID, HTTP: httpClient}
	runner := &reconciler.Runner{
		Client: client, BindingPath: *bindingPath, CommandKeyPath: *commandKeyPath,
		OperationID: *operationID, Phase: *phase,
	}
	if _, err := runner.Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
