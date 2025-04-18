package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	mockToken    = "testtoken"
	invalidToken = "invalid"
)

func mockServer() *httptest.Server {
	// In-memory store for test
	projects := map[string]map[string]string{}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth check
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != mockToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects" {
			var req struct{ OrgRepo string }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.OrgRepo == "" {
				http.Error(w, "missing orgRepo", http.StatusBadRequest)
				return
			}
			if _, exists := projects[req.OrgRepo]; !exists {
				projects[req.OrgRepo] = map[string]string{}
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/projects/") && strings.HasSuffix(r.URL.Path, "/keys") {
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) != 7 {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			orgRepo := parts[4] + "/" + parts[5]
			switch r.Method {
			case http.MethodPut:
				var keys map[string]string
				if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				if _, exists := projects[orgRepo]; !exists {
					projects[orgRepo] = map[string]string{}
				}
				for k, v := range keys {
					projects[orgRepo][k] = v
				}
				w.WriteHeader(http.StatusOK)
				return
			case http.MethodGet:
				secrets, exists := projects[orgRepo]
				if !exists {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(secrets)
				return
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

func TestAPIClient_Integration(t *testing.T) {
	ts := mockServer()
	defer ts.Close()

	client, err := NewAPIClient(ClientConfig{
		ServerURL: ts.URL,
		AuthToken: mockToken,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	ctx := context.Background()

	t.Run("CreateProject", func(t *testing.T) {
		err := client.CreateProject(ctx, "org/repo")
		if err != nil {
			t.Fatalf("CreateProject failed: %v", err)
		}
	})
	// Manually set project secrets in the mock server before pulling
	req, err := http.NewRequestWithContext(ctx, "PUT", ts.URL+"/api/v1/projects/org/repo/keys", strings.NewReader(`{"FOO":"bar","HELLO":"world"}`))
	if err != nil {
		t.Fatalf("failed to create PUT request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+mockToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to PUT secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status from PUT secrets: %d", resp.StatusCode)
	}

t.Run("PullKeys", func(t *testing.T) {
		secrets, err := client.PullKeys(ctx, "org/repo")
		if err != nil {
			t.Fatalf("PullKeys failed: %v", err)
		}
		if secrets["FOO"] != "bar" || secrets["HELLO"] != "world" {
			t.Errorf("unexpected secrets: %+v", secrets)
		}
	})
	t.Run("AuthFailure", func(t *testing.T) {
		badClient, _ := NewAPIClient(ClientConfig{ServerURL: ts.URL, AuthToken: invalidToken})
		err := badClient.CreateProject(ctx, "org/repo2")
		if err == nil || !strings.Contains(err.Error(), "unauthorized") {
			t.Error("expected unauthorized error, got", err)
		}
	})
	t.Run("ProjectNotFound", func(t *testing.T) {
		_, err := client.PullKeys(ctx, "org/doesnotexist")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Error("expected not found error, got", err)
		}
	})
}
