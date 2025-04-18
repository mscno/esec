package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mscno/esec/server/stores"
)

type Handler struct {
	Store     stores.Store
	userStore stores.UserStore
}

func NewHandler(store stores.Store, userStore stores.UserStore) *Handler {
	return &Handler{Store: store, userStore: userStore}
}

// ProjectKeysPerUser handles PUT/GET /api/v1/projects/{org}/{repo}/keys-per-user
func (h *Handler) ProjectKeysPerUser(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"), "/")
	if len(parts) != 3 || parts[2] != "keys-per-user" {
		http.NotFound(w, r)
		return
	}
	orgRepo := parts[0] + "/" + parts[1]

	if r.Method == http.MethodPut {
		token := extractBearerToken(r.Header.Get("Authorization"))
		userID := getGitHubIDFromToken(token)
		if !h.Store.IsProjectAdmin(orgRepo, userID) {
			http.Error(w, "only project admins may share secrets for this project", http.StatusForbidden)
			return
		}
		var payload map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Assume MemoryStore or BoltStore both implement SetPerUserSecrets
		if err := h.Store.(interface {
			SetPerUserSecrets(string, map[string]map[string]string) error
		}).SetPerUserSecrets(orgRepo, payload); err != nil {
			http.Error(w, "failed to store per-user secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	} else if r.Method == http.MethodGet {
		// Assume MemoryStore or BoltStore both implement GetPerUserSecrets
		payload, err := h.Store.(interface {
			GetPerUserSecrets(string) (map[string]map[string]string, error)
		}).GetPerUserSecrets(orgRepo)
		if err != nil {
			http.Error(w, "failed to get per-user secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
		return
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// CreateProject handles POST /api/v1/projects
func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type reqBody struct {
		OrgRepo string `json:"orgRepo"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateOrgRepo(req.OrgRepo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := extractBearerToken(r.Header.Get("Authorization"))
	if !userHasRepoAccess(token, req.OrgRepo) {
		http.Error(w, fmt.Sprintf("access to %s denied", req.OrgRepo), http.StatusForbidden)
		return
	}
	creatorID := getGitHubIDFromToken(token)
	if creatorID == "" {
		http.Error(w, "could not determine creator's GitHub ID", http.StatusUnauthorized)
		return
	}
	if err := h.Store.CreateProject(req.OrgRepo, creatorID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Project %s registered", req.OrgRepo)
}

// --- User Registration Handler ---
func (h *Handler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("missing or invalid Authorization header"))
		return
	}
	username, githubID, err := getUserInfo(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	if username == "" || githubID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields"))
		return
	}
	var publicKey string
	if err := json.NewDecoder(r.Body).Decode(&publicKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	user := stores.User{
		GitHubID:  githubID,
		Username:  username,
		PublicKey: publicKey,
	}
	err = h.userStore.RegisterUser(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to register user"))
		return
	}
	// Always update the public key (idempotent)
	_ = h.userStore.UpdateUserPublicKey(githubID, publicKey)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user registered"))
}

func getGitHubIDFromToken(token string) string {
	if token == "" {
		return ""
	}
	return token // stub for demo
}
