package middleware

import (
	"context"
	"encoding/json"
	"fmt"
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
	user      GithubUser
	valid     bool
	expiresAt time.Time
}

var (
	cacheMu       sync.Mutex
	validateCache = make(map[string]cacheEntry) // key: token or token+repo
)

func cacheGet(key string) (GithubUser, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	entry, ok := validateCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return GithubUser{}, false
	}
	return entry.user, entry.valid
}

func cacheSet(key string, user GithubUser, valid bool, ttl time.Duration) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	validateCache[key] = cacheEntry{user: user, valid: valid, expiresAt: time.Now().Add(ttl)}
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
type TokenValidator func(token string) (GithubUser, bool)

func WithGitHubAuth(next http.HandlerFunc, requireToken bool, validate TokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ExtractBearerToken(r.Header.Get("Authorization"))
		if requireToken {
			if token == "" {
				http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}
			user, valid := validate(token)
			if !valid {
				http.Error(w, "invalid GitHub token", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), "user", user)
			next(w, r.WithContext(ctx))
		} else {
			next(w, r)
		}
	}
}

func ExtractBearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

type GithubUser struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
}

// Real implementation: call GitHub API to validate token
func ValidateGitHubToken(token string) (GithubUser, bool) {
	slog.Info("validating GitHub token", "token", token)
	if token == "" {
		return GithubUser{}, false
	}
	cacheKey := token + "|validate"
	if user, valid := cacheGet(cacheKey); valid {
		return user, true
	}
	login, id, err := getUserInfo(token)
	valid := err == nil && login != ""
	slog.Info("validation result", "valid", valid, "login", login, "error", err)
	user := GithubUser{Login: login, ID: id}
	cacheSet(cacheKey, user, valid, 5*time.Minute)
	return user, valid
}

func getUserInfo(token string) (string, int, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	var user struct {
		Login string `json:"login"`
		ID    int    `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", 0, err
	}
	return user.Login, user.ID, nil
}
