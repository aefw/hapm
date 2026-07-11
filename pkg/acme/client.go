// Package acme menyediakan HTTP client untuk berkomunikasi dengan hapm-acme service.
// hapm-acme adalah service terpisah yang menjalankan LEGO CLI untuk proses ACME.
package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IssueRequest adalah request body untuk issue certificate baru
type IssueRequest struct {
	JobUUID     string   `json:"job_uuid"`
	CertUUID    string   `json:"cert_uuid"`
	Domains     []string `json:"domains"`
	Challenge   string   `json:"challenge"`
	CFToken     string   `json:"cf_token,omitempty"`
	Email       string   `json:"email"`
	Staging     bool     `json:"staging"`
	StoragePath string   `json:"storage_path"`
	WebRootPath string   `json:"webroot_path"`
}

// RenewRequest adalah request body untuk renew certificate
type RenewRequest struct {
	JobUUID     string   `json:"job_uuid"`
	CertUUID    string   `json:"cert_uuid"`
	Domains     []string `json:"domains"`
	Challenge   string   `json:"challenge"`
	CFToken     string   `json:"cf_token,omitempty"`
	Email       string   `json:"email"`
	Staging     bool     `json:"staging"`
	StoragePath string   `json:"storage_path"`
	WebRootPath string   `json:"webroot_path"`
}

// RevokeRequest adalah request body untuk revoke certificate
type RevokeRequest struct {
	JobUUID     string `json:"job_uuid"`
	CertUUID    string `json:"cert_uuid"`
	Domain      string `json:"domain"`
	Email       string `json:"email"`
	Staging     bool   `json:"staging"`
	StoragePath string `json:"storage_path"`
}

// ACMEResponse adalah response dari hapm-acme service
type ACMEResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Logs        string `json:"logs,omitempty"`
}

// Client adalah HTTP client untuk hapm-acme service
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient membuat instance Client baru
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Minute, // cukup untuk 1 retry + 30s wait + lego timeout
		},
	}
}

// Issue merequest penerbitan certificate baru ke hapm-acme
func (c *Client) Issue(ctx context.Context, req *IssueRequest) (*ACMEResponse, error) {
	return c.post(ctx, "/internal/issue", req)
}

// Renew merequest renewal certificate ke hapm-acme
func (c *Client) Renew(ctx context.Context, req *RenewRequest) (*ACMEResponse, error) {
	return c.post(ctx, "/internal/renew", req)
}

// Revoke merequest revoke certificate ke hapm-acme
func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*ACMEResponse, error) {
	return c.post(ctx, "/internal/revoke", req)
}

// Health memeriksa apakah hapm-acme service tersedia
func (c *Client) Health(ctx context.Context) error {
	resp, err := c.httpClient.Get(c.baseURL + "/internal/health")
	if err != nil {
		return fmt.Errorf("hapm-acme tidak tersedia: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hapm-acme health check gagal: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, body interface{}) (*ACMEResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("acme client: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("acme client: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme client: do: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("acme client: read response: %w", err)
	}

	var result ACMEResponse
	if err := json.Unmarshal(respData, &result); err != nil {
		return nil, fmt.Errorf("acme client: decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &result, fmt.Errorf("hapm-acme error: %s", result.Message)
	}

	return &result, nil
}
