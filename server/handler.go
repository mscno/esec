package server

import (
	"encoding/json"
	"fmt"
	"github.com/mscno/esec/server/middleware"
	"github.com/mscno/esec/server/stores"
	"log/slog"
	"net/http"
)

type UserHasRoleInRepoFunc func(token, orgRepo, role string) bool

type Handler struct {
	Store             stores.Store
	userStore         stores.UserStore
	logger            *slog.Logger
	userHasRoleInRepo UserHasRoleInRepoFunc
}

func NewHandler(store stores.Store, userStore stores.UserStore, userHasRoleInRepo UserHasRoleInRepoFunc) *Handler {
	if userHasRoleInRepo == nil {
		userHasRoleInRepo = defaultUserHasRoleInRepo
	}
	return &Handler{
		Store:             store,
		userStore:         userStore,
		logger:            slog.Default(),
		userHasRoleInRepo: userHasRoleInRepo,
	}
}

// ProjectKeysPerUserPut handles PUT /api/v1/projects/{org}/{repo}/keys-per-user
func (h *Handler) ProjectKeysPerUserPut(w http.ResponseWriter, r *http.Request) {
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

	user, ok := r.Context().Value("user").(middleware.GithubUser)
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
		h.logger.Error("failed to store per-user secrets", "orgRepo", orgRepo, "error", err.Error())
		http.Error(w, "failed to store per-user secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ProjectKeysPerUserGet handles GET /api/v1/projects/{org}/{repo}/keys-per-user
func (h *Handler) ProjectKeysPerUserGet(w http.ResponseWriter, r *http.Request) {
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

	user, ok := r.Context().Value("user").(middleware.GithubUser)
	if !ok {
		http.Error(w, "user info missing from context", http.StatusUnauthorized)
		return
	}
	h.logger.Info("extracted userID", "userID", user.ID)
	if !h.Store.IsProjectAdmin(orgRepo, fmt.Sprintf("%d", user.ID)) {
		http.Error(w, "only project admins may share secrets for this project", http.StatusForbidden)
		return
	}
	secrets, err := h.Store.GetPerUserSecrets(orgRepo)
	if err != nil {
		if err.Error() == "project not found" {
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get per-user secrets", "orgRepo", orgRepo, "error", err.Error())
		http.Error(w, "failed to get per-user secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(secrets); err != nil {
		h.logger.Error("failed to encode per-user secrets", "orgRepo", orgRepo, "error", err.Error())
		http.Error(w, "failed to encode per-user secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// CreateProject handles POST /api/v1/projects
func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
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
	user, ok := r.Context().Value("user").(middleware.GithubUser)
	if !ok {
		http.Error(w, "user info missing from context", http.StatusUnauthorized)
		return
	}

	if !h.userHasRoleInRepo(middleware.ExtractBearerToken(r.Header.Get("Authorization")), req.OrgRepo, "admin") {
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

// userHasRoleInRepo checks if the given GitHub token has a role in the given org/repo.
func defaultUserHasRoleInRepo(token, orgRepo string, role string) bool {
	if token == "" || orgRepo == "" || role == "" {
		return false
	}

	githubAPIURL := "https://api.github.com/repos/" + orgRepo
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	slog.Info("checking role in repo", "orgRepo", orgRepo, "role", role)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		slog.Warn("repo not found", "orgRepo", orgRepo)
		return false
	}

	if resp.StatusCode == http.StatusForbidden {
		slog.Warn("access to repo denied", "orgRepo", orgRepo)
		return false
	}

	var ghResp struct {
		Permissions struct {
			Admin bool `json:"admin"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return false
	}

	switch role {
	case "admin":
		return ghResp.Permissions.Admin
	case "read":
		return resp.StatusCode == http.StatusOK
	default:
		return false
	}
}

// --- User Registration Handler ---
func (h *Handler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ghuser, ok := r.Context().Value("user").(middleware.GithubUser)
	if !ok {
		slog.Error("user info missing from context")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var publicKey struct {
		Key string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&publicKey); err != nil {
		slog.Error("invalid JSON", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	user := stores.User{
		GitHubID:  fmt.Sprintf("%d", ghuser.ID),
		Username:  ghuser.Login,
		PublicKey: publicKey.Key,
	}
	err := h.userStore.RegisterUser(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to register user"))
		return
	}
	// Always update the public key (idempotent)
	_ = h.userStore.UpdateUserPublicKey(fmt.Sprintf("%d", ghuser.ID), publicKey.Key)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user registered"))
}
