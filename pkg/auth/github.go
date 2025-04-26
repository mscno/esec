package auth

import (
	"context"
	"errors"
	"fmt"

	// Import the consolidated keyring service
	"github.com/mscno/esec/pkg/oskeyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var ErrTokenNotFound = errors.New("authentication token not found in keyring")

// GithubProvider implements the Provider interface for GitHub authentication.
type GithubProvider struct {
	Config  Config
	keyring oskeyring.Service
}

// NewGithubProvider creates a new GithubProvider.
func NewGithubProvider(cfg Config, keyring oskeyring.Service) *GithubProvider {
	return &GithubProvider{
		Config:  cfg,
		keyring: keyring,
	}
}

func (p *GithubProvider) getOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID: p.Config.GithubClientID,
		Scopes:   []string{"repo"}, // Request repo scope for project validation
		Endpoint: github.Endpoint,
	}
}

// Login initiates the GitHub device flow.
func (p *GithubProvider) Login(ctx context.Context) error {
	if p.Config.GithubClientID == "" {
		return errors.New("GitHub Client ID is required for authentication")
	}

	oauthConfig := p.getOAuthConfig()

	deviceCode, err := oauthConfig.DeviceAuth(ctx)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	fmt.Printf("Please visit %s and enter the code: %s\n", deviceCode.VerificationURI, deviceCode.UserCode)
	fmt.Printf("Wait for the authentication to complete...\n")

	// Poll for the token
	token, err := oauthConfig.DeviceAccessToken(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	// Store the token in the keyring
	if err := p.keyring.Set(ServiceName, AccountName, token.AccessToken); err != nil {
		return fmt.Errorf("failed to store token in keyring: %w", err)
	}

	fmt.Println("Successfully authenticated and token stored.")
	return nil
}

// GetToken retrieves the stored GitHub token using the injected KeyringService.
func (p *GithubProvider) GetToken(ctx context.Context) (string, error) {
	token, err := p.keyring.Get(ServiceName, AccountName)
	if err != nil {
		if errors.Is(err, oskeyring.ErrNotFound) {
			return "", ErrTokenNotFound
		}
		return "", fmt.Errorf("failed to get token from keyring: %w", err)
	}
	return token, nil
}

// Logout removes the stored GitHub token using the injected KeyringService.
func (p *GithubProvider) Logout(ctx context.Context) error {
	err := p.keyring.Delete(ServiceName, AccountName)
	if err != nil {
		return fmt.Errorf("failed to delete token from keyring: %w", err)
	}
	fmt.Println("Successfully logged out and removed token.")
	return nil
}

// Ensure GithubProvider implements Provider interface
var _ Provider = (*GithubProvider)(nil)
