package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mscno/esec/server/stores"
)

type Handler struct {
	Store     stores.Store
	userStore stores.UserStore
	logger    *slog.Logger
}

func NewHandler(store stores.Store, userStore stores.UserStore) *Handler {
	return &Handler{Store: store, userStore: userStore, logger: slog.Default()}
}

// ProjectKeysPerUser handles PUT/GET /api/v1/projects/{org}/{repo}/keys-per-user
func (h *Handler) ProjectKeysPerUser(w http.ResponseWriter, r *http.Request) {
	// Use Go 1.23 ServeMux path variables
	org := r.PathValue("org")
	repo := r.PathValue("repo")
	// expects org/repo
	if org == "" || repo == "" {
		http.NotFound(w, r)
		return
	}
	orgRepo := org + "/" + repo
	if err := validateOrgRepo(orgRepo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !h.Store.ProjectExists(orgRepo) {
		h.logger.Error("project does not exist or you do not have access", "orgRepo", orgRepo)
		http.Error(w, "project does not exist or you do not have access", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodPut:
		user, ok := r.Context().Value("user").(githubUser)
		if !ok {
			http.Error(w, "user info missing from context", http.StatusUnauthorized)
			return
		}
		h.logger.Info("extracted userID", "userID", user.ID)
		if !h.Store.IsProjectAdmin(orgRepo, fmt.Sprintf("%d", user.ID)) {
			http.Error(w, "only project admins may share secrets for this project", http.StatusForbidden)
			return
		}
		var payload map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := h.Store.SetPerUserSecrets(orgRepo, payload); err != nil {
			http.Error(w, "failed to store per-user secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		payload, err := h.Store.GetPerUserSecrets(orgRepo)
		if err != nil {
			http.Error(w, "failed to get per-user secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
		return
	default:
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
	user, ok := r.Context().Value("user").(githubUser)
	if !ok {
		http.Error(w, "user info missing from context", http.StatusUnauthorized)
		return
	}
	if !userHasRepoAccess(extractBearerToken(r.Header.Get("Authorization")), req.OrgRepo) {
		http.Error(w, fmt.Sprintf("access to %s denied", req.OrgRepo), http.StatusForbidden)
		return
	}
	creatorID := fmt.Sprintf("%d", user.ID)
	if creatorID == "" || creatorID == "0" {
		h.logger.Error("could not determine creator's GitHub ID")
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
	ghuser, valid := ValidateGitHubToken(token)
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid GitHub token"))
		return
	}

	var publicKey string
	if err := json.NewDecoder(r.Body).Decode(&publicKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	user := stores.User{
		GitHubID:  fmt.Sprintf("%d", ghuser.ID),
		Username:  ghuser.Login,
		PublicKey: publicKey,
	}
	err := h.userStore.RegisterUser(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to register user"))
		return
	}
	// Always update the public key (idempotent)
	_ = h.userStore.UpdateUserPublicKey(fmt.Sprintf("%d", ghuser.ID), publicKey)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user registered"))
}
