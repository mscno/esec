package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mscno/esec/server/stores"
)

func setupTestHandler() *Handler {
	store := stores.NewMemoryStore()
	userStore := stores.NewMemoryUserStore()
	return NewHandler(store, userStore)
}

func mockTokenValidator(token string) (githubUser, bool) {
	if token == "testtoken" {
		return githubUser{Login: "testuser", ID: 42}, true
	}
	return githubUser{}, false
}

func TestCreateProject(t *testing.T) {
	h := setupTestHandler()
	// No need to pre-create project; this is the creation test
	r := httptest.NewRequest("POST", "/api/v1/projects", bytes.NewBufferString(`{"orgRepo":"foo/bar"}`))
	r.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	handler := WithGitHubAuth(h.CreateProject, true, mockTokenValidator)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 201/200, got %d", resp.StatusCode)
	}
}

func TestCreateProject_InvalidOrgRepo(t *testing.T) {
	h := setupTestHandler()
	h.Store.CreateProject("foo/bar", "42") // Ensure project exists before testing
	r := httptest.NewRequest("POST", "/api/v1/projects", bytes.NewBufferString(`{"orgRepo":"invalid"}`))
	r.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	handler := WithGitHubAuth(h.CreateProject, true, mockTokenValidator)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestProjectKeysPerUser_NotFound(t *testing.T) {
	h := setupTestHandler()
	h.Store.CreateProject("foo/bar", "42") // Ensure project exists before testing
	r := httptest.NewRequest("GET", "/api/v1/projects/foo/bar/keys-per-user", nil)
	r.SetPathValue("org", "foo")
	r.SetPathValue("repo", "bar")
	r.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	handler := WithGitHubAuth(h.ProjectKeysPerUser, true, mockTokenValidator)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestProjectKeysPerUser_PutGet(t *testing.T) {
	h := setupTestHandler()
	h.Store.CreateProject("foo/bar", "42") // Ensure project exists before testing
	// PUT per-user secrets
	secrets := map[string]map[string]string{"user1": {"KEY": "VAL"}}
	body, _ := json.Marshal(secrets)
	r := httptest.NewRequest("PUT", "/api/v1/projects/foo/bar/keys-per-user", bytes.NewBuffer(body))
	r.SetPathValue("org", "foo")
	r.SetPathValue("repo", "bar")
	r.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	handler := WithGitHubAuth(h.ProjectKeysPerUser, true, mockTokenValidator)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	// GET per-user secrets
	r = httptest.NewRequest("GET", "/api/v1/projects/foo/bar/keys-per-user", nil)
	r.SetPathValue("org", "foo")
	r.SetPathValue("repo", "bar")
	r.Header.Set("Authorization", "Bearer testtoken")
	w = httptest.NewRecorder()
	handler(w, r)
	resp = w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	var got map[string]map[string]string
	json.NewDecoder(resp.Body).Decode(&got)
	if got["user1"]["KEY"] != "VAL" {
		t.Fatalf("expected secret VAL, got %v", got)
	}
}
