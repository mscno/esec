package sync

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"encoding/json"
	"bytes"
	"io"
	"strings"
)

// Client defines the interface for interacting with the esec sync server.
type Client interface {
	// CreateProject registers a new project (org/repo) on the sync server.
	CreateProject(ctx context.Context, orgRepo string) error
	// PushKeys sends the provided key-value pairs to the sync server for the given project.
	PushKeys(ctx context.Context, orgRepo string, keys map[string]string) error
	// PullKeys retrieves the latest key-value pairs from the sync server for the given project.
	PullKeys(ctx context.Context, orgRepo string) (map[string]string, error)
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

// PushKeys sends key-value pairs to the sync server for the given project
func (c *APIClient) PushKeys(ctx context.Context, orgRepo string, keys map[string]string) error {
	if c.AuthToken == "" {
		return fmt.Errorf("authentication token required for PushKeys")
	}
	parts := strings.SplitN(orgRepo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid orgRepo format: %s", orgRepo)
	}
	url := c.ServerURL.ResolveReference(&url.URL{Path: "/api/v1/projects/" + parts[0] + "/" + parts[1] + "/keys"})
	body, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
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
	// Return dummy data for now
	// return map[string]string{"DUMMY_KEY_FROM_SERVER": "dummy_value"}, nil
	return nil, fmt.Errorf("PullKeys not implemented yet")
}

// Ensure APIClient implements Client interface
var _ Client = (*APIClient)(nil)
