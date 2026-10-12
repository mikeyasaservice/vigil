package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type TransportConfig struct {
	ManagementURL string
	ServerName    string
	SPIFFEID      string
	CAPath        string
	CertPath      string
	KeyPath       string
}

type Client struct {
	baseURL string
	http    *http.Client
}

type EnrollmentRequest struct {
	EnrollmentID              string `json:"enrollment_id"`
	EnrollmentToken           string `json:"enrollment_token"`
	AccountID                 string `json:"account_id"`
	LocalPolicyDigest         string `json:"local_policy_digest"`
	ConnectorPublicKey        string `json:"connector_public_key"`
	ProofSignature            string `json:"proof_signature"`
	CertificateSigningRequest string `json:"certificate_signing_request"`
}

type CertificateResponse struct {
	ClientCertificate    string `json:"client_certificate"`
	CACertificate        string `json:"ca_certificate"`
	CertificateExpiresAt string `json:"certificate_expires_at"`
	CertificateSerial    string `json:"certificate_serial"`
}

type EnrollmentResponse struct {
	CertificateResponse
	TenantID          string `json:"tenant_id"`
	DeploymentID      string `json:"deployment_id"`
	AccountID         string `json:"account_id"`
	ConnectorSPIFFEID string `json:"connector_spiffe_id"`
	ManagementEnabled bool   `json:"management_enabled"`
}

func NewClient(config TransportConfig) (*Client, error) {
	parsed, err := url.Parse(config.ManagementURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("management URL must be an explicit HTTPS origin")
	}
	loadCertificate := func() (*tls.Certificate, error) {
		certificate, loadErr := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if loadErr != nil || len(certificate.Certificate) == 0 {
			return nil, fmt.Errorf("connector client certificate is unavailable")
		}
		leaf, parseErr := x509.ParseCertificate(certificate.Certificate[0])
		if parseErr != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != config.SPIFFEID {
			return nil, fmt.Errorf("connector certificate does not match its trusted SPIFFE binding")
		}
		return &certificate, nil
	}
	if _, err := loadCertificate(); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(config.CAPath)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("management CA bundle is unavailable")
	}
	return &Client{
		baseURL: strings.TrimRight(config.ManagementURL, "/"),
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: config.ServerName,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return loadCertificate() },
		}}},
	}, nil
}

func (c *Client) post(ctx context.Context, path string, requestBody, responseBody any) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("management endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(responseBody)
}

func (c *Client) SendHealth(ctx context.Context, deploymentID string, event HealthEvent) (map[string]any, error) {
	var receipt map[string]any
	err := c.post(ctx, "/internal/v1/byoc/deployments/"+url.PathEscape(deploymentID)+"/health", event, &receipt)
	return receipt, err
}

func (c *Client) Enroll(ctx context.Context, request EnrollmentRequest) (EnrollmentResponse, error) {
	var response EnrollmentResponse
	err := c.post(ctx, "/internal/v1/byoc/enroll", request, &response)
	return response, err
}

func (c *Client) RotateCertificate(ctx context.Context, deploymentID, csr string) (CertificateResponse, error) {
	var response CertificateResponse
	err := c.post(ctx, "/internal/v1/byoc/deployments/"+url.PathEscape(deploymentID)+"/certificate/rotate", map[string]string{
		"certificate_signing_request": csr,
	}, &response)
	return response, err
}
