package auth

import "context"

const (
	ServiceName  = "esec-sync"
	GithubToken  = "github_token"
	GithubUserID = "github_user_id"
	GithubLogin  = "github_login"
)

// Provider defines the interface for authentication providers.
type Provider interface {
	// Login initiates the authentication flow and stores the token.
	Login(ctx context.Context) error
	// GetToken retrieves the stored authentication token.
	GetToken(ctx context.Context) (string, error)
	// GetUserID retrieves the stored GitHub User ID.
	GetUserID(ctx context.Context) (string, error)
	// GetGithubLogin retrieves the stored GitHub Login.
	GetGithubLogin(ctx context.Context) (string, error)
	// Logout removes the stored authentication token and user identifiers.
	Logout(ctx context.Context) error
}

// Config holds configuration for the auth package.
type Config struct {
	GithubClientID     string
	GithubClientSecret string // Optional, might be needed for some flows
}
