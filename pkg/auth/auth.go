package auth

import "context"

const (
	ServiceName = "esec-sync"
	AccountName = "github_token"
)

// Provider defines the interface for authentication providers.
type Provider interface {
	// Login initiates the authentication flow and stores the token.
	Login(ctx context.Context) error
	// GetToken retrieves the stored authentication token.
	GetToken(ctx context.Context) (string, error)
	// Logout removes the stored authentication token.
	Logout(ctx context.Context) error
}

// Config holds configuration for the auth package.
type Config struct {
	GithubClientID     string
	GithubClientSecret string // Optional, might be needed for some flows
}
