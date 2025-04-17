package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/mscno/esec/pkg/store"
) // unchanged, for clarity


// Store interface abstracts project/secret storage
// (can be swapped for persistent implementations)
type Store interface {
	CreateProject(orgRepo string, adminID string) error
	ProjectExists(orgRepo string) bool
	GetSecrets(orgRepo string) (map[string]string, error)
	SetSecrets(orgRepo string, secrets map[string]string) error
	GetProjectAdmins(orgRepo string) ([]string, error)
	IsProjectAdmin(orgRepo string, githubID string) bool
} // now supports project admins

// memoryStore implements Store using in-memory maps
// (not safe for multi-process, but fine for demo/testing)
type ProjectMeta struct {
	Admins []string `json:"admins"`
}

type memoryStore struct {
	mu       sync.RWMutex
	projects map[string]map[string]string // key: org/repo
	perUser  map[string]map[string]map[string]string // org/repo -> user -> key -> value
	meta     map[string]*ProjectMeta // org/repo -> metadata (admins, etc.)
}

func (m *memoryStore) GetProjectAdmins(orgRepo string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	meta, exists := m.meta[orgRepo]
	if !exists || meta == nil {
		return nil, fmt.Errorf("project not found")
	}
	return append([]string{}, meta.Admins...), nil
}

func (m *memoryStore) IsProjectAdmin(orgRepo string, githubID string) bool {
	admins, err := m.GetProjectAdmins(orgRepo)
	if err != nil {
		return false
	}
	for _, admin := range admins {
		if admin == githubID {
			return true
		}
	}
	return false
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		projects: make(map[string]map[string]string),
		perUser:  make(map[string]map[string]map[string]string),
		meta:     make(map[string]*ProjectMeta),
	}
} // now initializes meta

func (m *memoryStore) CreateProject(orgRepo string, adminID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.projects[orgRepo]; !exists {
		m.projects[orgRepo] = make(map[string]string)
		m.meta[orgRepo] = &ProjectMeta{Admins: []string{adminID}}
	}
	return nil
} // stores creator as admin
func (m *memoryStore) ProjectExists(orgRepo string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.projects[orgRepo]
	return exists
}
func (m *memoryStore) GetSecrets(orgRepo string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secrets, exists := m.projects[orgRepo]
	if !exists {
		return nil, fmt.Errorf("project not found")
	}
	// Return a copy to avoid race
	copy := make(map[string]string, len(secrets))
	for k, v := range secrets {
		copy[k] = v
	}
	return copy, nil
}
func (m *memoryStore) SetSecrets(orgRepo string, secrets map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.projects[orgRepo]; !exists {
		return fmt.Errorf("project not found")
	}
	for k, v := range secrets {
		m.projects[orgRepo][k] = v
	}
	return nil
}

// Per-user secrets for in-memory store
func (m *memoryStore) GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	perUser, exists := m.perUser[orgRepo]
	if !exists {
		return make(map[string]map[string]string), nil
	}
	// Deep copy to avoid race
	copy := make(map[string]map[string]string, len(perUser))
	for user, secrets := range perUser {
		secretsCopy := make(map[string]string, len(secrets))
		for k, v := range secrets {
			secretsCopy[k] = v
		}
		copy[user] = secretsCopy
	}
	return copy, nil
}

func (m *memoryStore) SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Deep copy for safety
	copy := make(map[string]map[string]string, len(secrets))
	for user, sec := range secrets {
		secCopy := make(map[string]string, len(sec))
		for k, v := range sec {
			secCopy[k] = v
		}
		copy[user] = secCopy
	}
	m.perUser[orgRepo] = copy
	return nil
}


var projectFormat = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

func main() {
	// --- User store ---
	userStore := store.NewMemoryUserStore()

	// Choose store implementation
	var s Store
	storeType := os.Getenv("ESEC_STORE")
	if storeType == "bolt" {
		boltPath := os.Getenv("ESEC_BOLT_PATH")
		if boltPath == "" {
			boltPath = "esec.db"
		}
		boltStore, err := store.NewBoltStore(boltPath)
		if err != nil {
			log.Fatalf("failed to open BoltDB: %v", err)
		}
		defer boltStore.Close()
		s = boltStore
		log.Printf("Using BoltDB store at %s", boltPath)
	} else {
		s = newMemoryStore()
		log.Printf("Using in-memory store")
	}

	// --- Endpoints ---
	// 1. Project creation
	http.HandleFunc("/api/v1/projects", withGitHubAuth(func(w http.ResponseWriter, r *http.Request) {
		handleCreateProject(w, r, s)
	}, false)) // Project creation does not require token (for demo)

	// 2. Project secrets (push/pull)
	http.HandleFunc("/api/v1/projects/", withGitHubAuth(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys-per-user") {
			handleProjectKeysPerUser(w, r, s)
		} else if strings.HasSuffix(r.URL.Path, "/keys") {
			handleProjectKeys(w, r, s)
		} else {
			http.NotFound(w, r)
		}
	}, true)) // Require GitHub token for secret ops

	// 3. User registration
	http.HandleFunc("/api/v1/users/register", func(w http.ResponseWriter, r *http.Request) {
		handleUserRegister(w, r, userStore)
	})

	addr := ":8080"
	log.Printf("Esec Sync Server listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleProjectKeys(w http.ResponseWriter, r *http.Request, store Store) {

	// Path: /api/v1/projects/{org}/{repo}/keys
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"), "/")
	if len(parts) != 3 || parts[2] != "keys" {
		http.NotFound(w, r)
		return
	}
	orgRepo := parts[0] + "/" + parts[1]
	token := extractBearerToken(r.Header.Get("Authorization"))
	if !userHasRepoAccess(token, orgRepo) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !store.ProjectExists(orgRepo) {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		// Admin check
		userID := getGitHubIDFromToken(token)
		if !store.IsProjectAdmin(orgRepo, userID) {
			http.Error(w, "only project admins may push secrets to this project", http.StatusForbidden)
			return
		}
		// Push keys
		var secrets map[string]string
		if err := json.NewDecoder(r.Body).Decode(&secrets); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := store.SetSecrets(orgRepo, secrets); err != nil {
			http.Error(w, "failed to store secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	} else if r.Method == http.MethodGet {
		// Pull keys
		secrets, err := store.GetSecrets(orgRepo)
		if err != nil {
			http.Error(w, "failed to get secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secrets)
		return
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// POST /api/v1/projects
func handleCreateProject(w http.ResponseWriter, r *http.Request, store Store) {
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

	// Check if user can access repo on GitHub
	token := extractBearerToken(r.Header.Get("Authorization"))
	if !userHasRepoAccess(token, req.OrgRepo) {
		http.Error(w, fmt.Sprintf("access to %s denied", req.OrgRepo), http.StatusForbidden)
		return
	}

	// Get creator's GitHub ID (stub: in real implementation, extract from token)
	creatorID := getGitHubIDFromToken(token)
	if creatorID == "" {
		http.Error(w, "could not determine creator's GitHub ID", http.StatusUnauthorized)
		return
	}

	if err := store.CreateProject(req.OrgRepo, creatorID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Project %s registered", req.OrgRepo)
}

// getGitHubIDFromToken is a stub. Replace with real GitHub API call.
func getGitHubIDFromToken(token string) string {
	// TODO: implement real logic
	if token == "" {
		return ""
	}
	return token // for demo/testing, treat token as GitHub ID
}

// PUT/GET /api/v1/projects/{org}/{repo}/keys-per-user
func handleProjectKeysPerUser(w http.ResponseWriter, r *http.Request, storeIface interface{}) {
	// Path: /api/v1/projects/{org}/{repo}/keys-per-user
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"), "/")
	if len(parts) != 3 || parts[2] != "keys-per-user" {
		http.NotFound(w, r)
		return
	}
	orgRepo := parts[0] + "/" + parts[1]

	switch store := storeIface.(type) {
	case *memoryStore:
		if !store.ProjectExists(orgRepo) {
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			// Admin check
			token := extractBearerToken(r.Header.Get("Authorization"))
			userID := getGitHubIDFromToken(token)
			if !store.IsProjectAdmin(orgRepo, userID) {
				http.Error(w, "only project admins may share secrets for this project", http.StatusForbidden)
				return
			}
			var payload map[string]map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if err := store.SetPerUserSecrets(orgRepo, payload); err != nil {
				http.Error(w, "failed to store per-user secrets: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == http.MethodGet {
			payload, err := store.GetPerUserSecrets(orgRepo)
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
	case *store.BoltStore:
		if !store.ProjectExists(orgRepo) {
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			// Admin check
			token := extractBearerToken(r.Header.Get("Authorization"))
			userID := getGitHubIDFromToken(token)
			if !store.IsProjectAdmin(orgRepo, userID) {
				http.Error(w, "only project admins may share secrets for this project", http.StatusForbidden)
				return
			}
			var payload map[string]map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if err := store.SetPerUserSecrets(orgRepo, payload); err != nil {
				http.Error(w, "failed to store per-user secrets: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == http.MethodGet {
			payload, err := store.GetPerUserSecrets(orgRepo)
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
	default:
		http.Error(w, "unsupported store type", http.StatusInternalServerError)
		return
	}
}

// PUT/GET /api/v1/projects/{org}/{repo}/keys
// func handleProjectKeys(w http.ResponseWriter, r *http.Request, store Store) {
// 	// Path: /api/v1/projects/{org}/{repo}/keys
// 	parts := strings.Split(r.URL.Path, "/")
// 	if len(parts) != 7 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "projects" || parts[6] != "keys" {
// 		http.Error(w, "not found", http.StatusNotFound)
// 		return
// 	}
// 	org, repo := parts[4], parts[5]
// 	orgRepo := org + "/" + repo
// 	if err := validateOrgRepo(orgRepo); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	switch r.Method {
// 	case http.MethodPut:
// 		var newSecrets map[string]string
// 		if err := json.NewDecoder(r.Body).Decode(&newSecrets); err != nil {
// 			http.Error(w, "invalid JSON", http.StatusBadRequest)
// 			return
// 		}
// 		if err := store.SetSecrets(orgRepo, newSecrets); err != nil {
// 			http.Error(w, err.Error(), http.StatusNotFound)
// 			return
// 		}
// 		w.WriteHeader(http.StatusOK)
// 		fmt.Fprintf(w, "Secrets updated for project %s", orgRepo)
// 	case http.MethodGet:
// 		secrets, err := store.GetSecrets(orgRepo)
// 		if err != nil {
// 			http.Error(w, err.Error(), http.StatusNotFound)
// 			return
// 		}
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(secrets)
// 	default:
// 		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
// 	}
// }

func validateOrgRepo(orgRepo string) error {
	if !projectFormat.MatchString(orgRepo) {
		return fmt.Errorf("invalid project format: must be 'org/repo'")
	}
	return nil
}

// --- User Registration Handler ---
func handleUserRegister(w http.ResponseWriter, r *http.Request, userStore store.UserStore) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	type reqBody struct {
		GitHubID  string `json:"github_id"`
		Username  string `json:"username"`
		PublicKey string `json:"public_key"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	if req.GitHubID == "" || req.Username == "" || req.PublicKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields"))
		return
	}
	user := store.User{
		GitHubID:  req.GitHubID,
		Username:  req.Username,
		PublicKey: req.PublicKey,
	}
	err := userStore.RegisterUser(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to register user"))
		return
	}
	// Always update the public key (idempotent)
	_ = userStore.UpdateUserPublicKey(req.GitHubID, req.PublicKey)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user registered"))
}

// --- GitHub Token Validation Middleware ---

// withGitHubAuth wraps handlers with GitHub Bearer token validation.
// If requireToken is true, rejects if token is missing or invalid.
func withGitHubAuth(next http.HandlerFunc, requireToken bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r.Header.Get("Authorization"))
		if requireToken {
			if token == "" {
				http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}
			if !validateGitHubToken(token) {
				http.Error(w, "invalid GitHub token", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func extractBearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

// userHasRepoAccess checks if the given GitHub token has access to orgRepo ("org/repo").
func userHasRepoAccess(token, orgRepo string) bool {
	if token == "" || orgRepo == "" {
		return false
	}
	githubAPIURL := "https://api.github.com/repos/" + orgRepo
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Real implementation: call GitHub API to validate token
func validateGitHubToken(token string) bool {
	if token == "" {
		return false
	}
	// Make a request to GitHub API (user endpoint)
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
