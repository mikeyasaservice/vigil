package reconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	BaseURL  string
	RunnerID string
	HTTP     *http.Client
}

func (c *Client) call(ctx context.Context, method, path string, requestBody, responseBody any) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vigil-Runner-Id", c.RunnerID)
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("management API returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if responseBody == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(responseBody)
}

func (c *Client) Claim(ctx context.Context, operationID, phase string) (ClaimResponse, error) {
	var response ClaimResponse
	err := c.call(ctx, http.MethodPost, "/internal/v1/operations/"+operationID+"/claim", map[string]any{
		"phase": phase, "runner_id": c.RunnerID,
	}, &response)
	return response, err
}

func (c *Client) PlanReady(ctx context.Context, operationID, commandID string, fencingToken int64, manifestDigest, planHash string) error {
	return c.call(ctx, http.MethodPost, "/internal/v1/operations/"+operationID+"/plan-ready", map[string]any{
		"command_id": commandID, "fencing_token": fencingToken, "manifest_digest": manifestDigest, "plan_hash": planHash,
	}, &map[string]any{})
}

func (c *Client) Complete(ctx context.Context, operationID string, receipt Receipt) error {
	return c.call(ctx, http.MethodPost, "/internal/v1/operations/"+operationID+"/complete", receipt, &map[string]any{})
}

func (c *Client) Fail(ctx context.Context, operationID, commandID string, fencingToken int64, phase, code, detail string) error {
	return c.call(ctx, http.MethodPost, "/internal/v1/operations/"+operationID+"/fail", map[string]any{
		"command_id": commandID, "fencing_token": fencingToken, "phase": phase, "error_code": code, "error_detail": detail,
	}, &map[string]any{})
}
