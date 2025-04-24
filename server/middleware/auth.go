package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// withGitHubAuth wraps handlers with GitHub Bearer token validation.
// If requireToken is true, rejects if token is missing or invalid.
type TokenValidator func(token string) (GithubUser, bool)

func WithGitHubAuth(validate TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r.Header.Get("Authorization"))
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
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

type GithubUser struct {
	Token string
	Login string
	ID    int
}

// Real implementation: call GitHub API to validate token
func ValidateGitHubToken(token string) (GithubUser, bool) {
	slog.Info("validating GitHub token", "token", token)
	if token == "" {
		return GithubUser{}, false
	}

	login, id, err := getUserInfo(token)
	valid := err == nil && login != ""
	slog.Info("validation result", "valid", valid, "login", login, "error", err)
	user := GithubUser{Login: login, ID: id, Token: token}
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
