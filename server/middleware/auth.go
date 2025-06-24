package middleware

import (
	"context"

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
	if token == "" {
		return GithubUser{}, false
	}
	login, id, err := GetUserInfo(token)
	valid := err == nil && login != ""
	user := GithubUser{Login: login, ID: id, Token: token}
	return user, valid
}
