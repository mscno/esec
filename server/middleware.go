package server

import (
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PanicRecoveryMiddleware recovers from panics and returns HTTP 500
func PanicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs incoming HTTP requests with method, path, status, and duration
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, duration)
	})
}

// --- Simple in-memory cache for GitHub token validation and repo access ---
type cacheEntry struct {
	value     bool
	expiresAt time.Time
}

var (
	cacheMu       sync.Mutex
	validateCache = make(map[string]cacheEntry) // key: token or token+repo
)

func cacheGet(key string) (bool, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	entry, ok := validateCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, false
	}
	return entry.value, true
}

func cacheSet(key string, value bool, ttl time.Duration) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	validateCache[key] = cacheEntry{value: value, expiresAt: time.Now().Add(ttl)}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- GitHub Token Validation Middleware ---

// withGitHubAuth wraps handlers with GitHub Bearer token validation.
// If requireToken is true, rejects if token is missing or invalid.
func WithGitHubAuth(next http.HandlerFunc, requireToken bool) http.HandlerFunc {
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
	cacheKey := token + "|repo|" + orgRepo
	if val, ok := cacheGet(cacheKey); ok {
		return val
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
	allowed := resp.StatusCode == http.StatusOK
	cacheSet(cacheKey, allowed, 5*time.Minute)
	return allowed
}

// Real implementation: call GitHub API to validate token
func validateGitHubToken(token string) bool {
	slog.Info("validating GitHub token", "token", token)
	if token == "" {
		return false
	}
	cacheKey := token + "|validate"
	if val, ok := cacheGet(cacheKey); ok {
		return val
	}
	login, _, err := getUserInfo(token)
	valid := err == nil && login != ""
	slog.Info("validation result", "valid", valid, "login", login, "error", err)
	cacheSet(cacheKey, valid, 5*time.Minute)
	return valid
}
