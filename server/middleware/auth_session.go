package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mscno/esec/pkg/session" // New import for session validation
)

// AppSessionUser holds user information derived from an app-managed session token.
type AppSessionUser struct {
	GithubUserID string
	GithubLogin  string
}

// AppSessionValidator defines the function signature for validating an app session token.
type AppSessionValidator func(ctx context.Context, token string) (AppSessionUser, bool)

// WithAppSessionAuth wraps handlers with app-managed session token validation.
// If a valid session token is present, user information is added to the context.
// If the token is missing or invalid, the request proceeds, but no user info is added.
// Individual handlers are responsible for checking if auth is required and user info is present.
func WithAppSessionAuth(validate AppSessionValidator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r.Header.Get("Authorization"))
			userCtx := r.Context() // Start with the original context

			if token != "" {
				user, valid := validate(r.Context(), token)
				if valid {
					userCtx = context.WithValue(r.Context(), "user", user) // User userCtx for clarity
					logger.DebugContext(userCtx, "App session authenticated", "user", user.GithubLogin, "id", user.GithubUserID)
				} else {
					// Token was present but invalid.
					// For ConnectRPC, it's often better to let the handler return CodeUnauthenticated
					// if it requires auth, rather than the middleware short-circuiting here with HTTP error.
					// If we wanted to deny here for invalid tokens:
					// http.Error(w, "Invalid session token", http.StatusUnauthorized)
					// return
					logger.WarnContext(userCtx, "Invalid app session token presented")
				}
			} else {
				logger.DebugContext(userCtx, "No app session token found in request header")
			}
			next.ServeHTTP(w, r.WithContext(userCtx))
		})
	}
}

// DefaultAppSessionValidator uses the pkg/session to validate JWTs.
func DefaultAppSessionValidator(ctx context.Context, token string) (AppSessionUser, bool) {
	claims, err := session.ValidateToken(token)
	if err != nil {
		slog.DebugContext(ctx, "App session token validation failed", "error", err)
		return AppSessionUser{}, false
	}
	return AppSessionUser{
		GithubUserID: claims.GithubUserID,
		GithubLogin:  claims.GithubLogin,
	}, true
}

// GetUserInfo fetches user details from GitHub API.
func GetUserInfo(token string) (string, int, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json") // Corrected Accept header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	var user struct {
		Login string `json:"login"`
		ID    int    `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", 0, err
	}
	if user.Login == "" || user.ID == 0 {
		return "", 0, fmt.Errorf("GitHub user login or ID not found in response")
	}
	return user.Login, user.ID, nil
}
