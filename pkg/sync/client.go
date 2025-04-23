package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Client defines the interface for interacting with the esec sync server.
type Client interface {
	// CreateProject registers a new project (org/repo) on the sync server.
	CreateProject(ctx context.Context, orgRepo string) error
	// PullKeys retrieves the latest key-value pairs from the sync server for the given project.
	PullKeys(ctx context.Context, orgRepo string) (map[string]string, error)
	// GetUserPublicKey fetches a user's public key by username or GitHub ID.
	GetUserPublicKey(ctx context.Context, usernameOrID string) (publicKey, githubID, username string, err error)
	// PushKeysPerUser sends per-recipient encrypted secrets to the sync server for the given project.
	PushKeysPerUser(ctx context.Context, orgRepo string, perUserPayload map[string]map[string]string) error
	// PullKeysPerUser fetches per-recipient encrypted secrets from the sync server for the given project.
	PullKeysPerUser(ctx context.Context, orgRepo string) (map[string]map[string]string, error)
}

// APIClient implements the Client interface for the esec sync API.
type APIClient struct {
	ServerURL  *url.URL
	AuthToken  string
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// ClientConfig holds configuration for creating a new APIClient.
type ClientConfig struct {
	ServerURL string
	AuthToken string
	Logger    *slog.Logger
}

// NewAPIClient creates a new API client instance.
func NewAPIClient(config ClientConfig) (*APIClient, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	serverURL, err := url.Parse(config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if config.AuthToken == "" {
		// Depending on the operation, token might not always be required (e.g., server status check?)
		// For now, let's log a warning but allow creation.
		config.Logger.Warn("Auth token is empty. Authenticated operations will fail.")
	}

	return &APIClient{
		ServerURL:  serverURL,
		AuthToken:  config.AuthToken,
		HTTPClient: &http.Client{}, // Use default client for now
		Logger:     config.Logger,
	}, nil
}

// CreateProject creates a new project on the sync server
func (c *APIClient) CreateProject(ctx context.Context, orgRepo string) error {
	if c.AuthToken == "" {
		return fmt.Errorf("authentication token required for CreateProject")
	}
	url := c.ServerURL.ResolveReference(&url.URL{Path: "/api/v1/projects"})
	body := map[string]string{"orgRepo": orgRepo}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s: %s", resp.Status, string(respBytes))
	}
	return nil
}

// PullKeys retrieves key-value pairs from the sync server for the given project
func (c *APIClient) PullKeys(ctx context.Context, orgRepo string) (map[string]string, error) {
	if c.AuthToken == "" {
		return nil, fmt.Errorf("authentication token required for PullKeys")
	}
	parts := strings.SplitN(orgRepo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid orgRepo format: %s", orgRepo)
	}
	url := c.ServerURL.ResolveReference(&url.URL{Path: "/api/v1/projects/" + parts[0] + "/" + parts[1] + "/keys"})
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error: %s: %s", resp.Status, string(respBytes))
	}
	var secrets map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return secrets, nil
}

// GetUserPublicKey fetches a user's public key by username or GitHub ID.
func (c *APIClient) GetUserPublicKey(ctx context.Context, usernameOrID string) (publicKey, githubID, username string, err error) {
	endpoint := c.ServerURL.String() + "/api/v1/users/" + usernameOrID + "/public-key"
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("failed to get user public key: %s", string(body))
	}
	var data struct {
		PublicKey string `json:"publicKey"`
		GitHubID  string `json:"githubID"`
		Username  string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", "", err
	}
	return data.PublicKey, data.GitHubID, data.Username, nil
}

// PushKeysPerUser sends per-recipient encrypted secrets to the sync server for the given project.
func (c *APIClient) PushKeysPerUser(ctx context.Context, orgRepo string, perUserPayload map[string]map[string]string) error {
	if c.AuthToken == "" {
		return fmt.Errorf("authentication token required for PushKeysPerUser")
	}
	parts := strings.SplitN(orgRepo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid orgRepo format: %s", orgRepo)
	}
	url := c.ServerURL.ResolveReference(&url.URL{Path: "/api/v1/projects/" + parts[0] + "/" + parts[1] + "/keys-per-user"})
	body, err := json.Marshal(perUserPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal per-user payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", url.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s: %s", resp.Status, string(respBytes))
	}
	return nil
}

// PullKeysPerUser fetches per-recipient encrypted secrets from the sync server for the given project.
func (c *APIClient) PullKeysPerUser(ctx context.Context, orgRepo string) (map[string]map[string]string, error) {
	if c.AuthToken == "" {
		return nil, fmt.Errorf("authentication token required for PullKeysPerUser")
	}
	parts := strings.SplitN(orgRepo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid orgRepo format: %s", orgRepo)
	}
	url := c.ServerURL.ResolveReference(&url.URL{Path: "/api/v1/projects/" + parts[0] + "/" + parts[1] + "/keys-per-user"})
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error: %s: %s", resp.Status, string(respBytes))
	}
	var payload map[string]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return payload, nil
}

// Ensure APIClient implements Client interface
var _ Client = (*APIClient)(nil)
