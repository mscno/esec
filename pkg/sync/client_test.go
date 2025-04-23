package sync

import (
	"context"
	"github.com/go-michi/michi"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/stores"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func setupTestServerAndClient() (*httptest.Server, *APIClient, stores.UserStore) {
	userStore := stores.NewMemoryUserStore()
	h := server.NewHandler(stores.NewMemoryStore(), userStore, nil)
	mux := michi.NewRouter()
	mux.Handle("/api/v1/users/{github_id}/public-key", http.HandlerFunc(h.GetUserPublicKey))
	ts := httptest.NewServer(mux)
	parsed, _ := url.Parse(ts.URL)
	client := &APIClient{
		ServerURL:  parsed,
		HTTPClient: ts.Client(),
		Logger:     slog.Default(),
	}
	return ts, client, userStore
}

func TestAPIClient_GetUserPublicKey(t *testing.T) {
	ts, client, userStore := setupTestServerAndClient()
	defer ts.Close()
	user := stores.User{GitHubID: "123", Username: "alice", PublicKey: "ssh-ed25519 AAAA..."}
	userStore.RegisterUser(user)
	pub, gid, uname, err := client.GetUserPublicKey(context.Background(), "123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub != user.PublicKey {
		t.Errorf("expected publicKey %q, got %q", user.PublicKey, pub)
	}
	if gid != user.GitHubID {
		t.Errorf("expected githubID %q, got %q", user.GitHubID, gid)
	}
	if uname != user.Username {
		t.Errorf("expected username %q, got %q", user.Username, uname)
	}
}

func TestAPIClient_GetUserPublicKey_NotFound(t *testing.T) {
	ts, client, _ := setupTestServerAndClient()
	defer ts.Close()
	_, _, _, err := client.GetUserPublicKey(context.Background(), "999")
	if err == nil {
		t.Fatalf("expected error for missing user, got nil")
	}
}
