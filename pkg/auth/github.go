package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	// Import the consolidated keyring service
	"github.com/mscno/esec/pkg/oskeyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var ErrTokenNotFound = errors.New("authentication token not found in keyring")
var ErrUserInfoNotFound = errors.New("user info (ID or Login) not found in keyring")

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

	// Fetch user ID and login using the new token
	userID, userLogin, err := fetchGitHubUserInfo(ctx, token.AccessToken) // Use ctx here
	if err != nil {
		// Log the error but proceed to store the token, as auth itself might have succeeded.
		// The user ID/login can be fetched later via GetUserID/GetGithubLogin.
		fmt.Printf("Warning: failed to fetch GitHub user info immediately after login: %v\n", err)
		// It's important to decide if this should be a hard error for Login.
		// For now, we'll allow login to succeed if token is obtained, but user info is missing.
	}

	// Store the token in the keyring
	if err := p.keyring.Set(ServiceName, GithubToken, token.AccessToken); err != nil {
		return fmt.Errorf("failed to store token in keyring: %w", err)
	}

	// Store user ID and login if fetched successfully
	if userID != "" {
		if err := p.keyring.Set(ServiceName, GithubUserID, userID); err != nil {
			// Log error, but token is stored.
			fmt.Printf("Warning: failed to store GitHub User ID in keyring: %v\n", err)
		}
	}
	if userLogin != "" {
		if err := p.keyring.Set(ServiceName, GithubLogin, userLogin); err != nil {
			// Log error, but token is stored.
			fmt.Printf("Warning: failed to store GitHub Login in keyring: %v\n", err)
		}
	}

	fmt.Println("Successfully authenticated and token stored.")
	if userID != "" && userLogin != "" {
		fmt.Printf("User ID: %s, Login: %s also stored.\n", userID, userLogin)
	}
	return nil
}

// fetchGitHubUserInfo retrieves the user ID and login from GitHub using the provided token.
// It now accepts a context.
func fetchGitHubUserInfo(ctx context.Context, token string) (string, string, error) {
	if token == "" {
		return "", "", errors.New("token cannot be empty")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil) // Use ctx
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var userInfo struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", fmt.Errorf("failed to decode GitHub user info: %w", err)
	}

	if userInfo.ID == 0 {
		return "", "", fmt.Errorf("GitHub user ID not found in response")
	}
	if userInfo.Login == "" {
		return "", "", fmt.Errorf("GitHub user login not found in response")
	}

	return fmt.Sprintf("%d", userInfo.ID), userInfo.Login, nil
}

// GetToken retrieves the stored GitHub token using the injected KeyringService.
func (p *GithubProvider) GetToken(ctx context.Context) (string, error) {
	token, err := p.keyring.Get(ServiceName, GithubToken)
	if err != nil {
		if errors.Is(err, oskeyring.ErrNotFound) {
			return "", ErrTokenNotFound
		}
		return "", fmt.Errorf("failed to get token from keyring: %w", err)
	}
	return token, nil
}

// GetUserID retrieves the stored GitHub User ID.
// It attempts to fetch from GitHub if not found in keyring but a token exists.
func (p *GithubProvider) GetUserID(ctx context.Context) (string, error) {
	userID, err := p.keyring.Get(ServiceName, GithubUserID)
	if err == nil && userID != "" {
		return userID, nil // Found in keyring
	}

	// Not in keyring or error retrieving, try to fetch if token exists
	if !errors.Is(err, oskeyring.ErrNotFound) && err != nil {
		// Some other error with keyring for UserID, don't fallback to token fetch for this specific error.
		return "", fmt.Errorf("failed to get UserID from keyring: %w", err)
	}

	// Attempt to fetch using token
	token, tokenErr := p.GetToken(ctx)
	if tokenErr != nil {
		return "", fmt.Errorf("cannot fetch UserID without token: %w", tokenErr)
	}

	fetchedUserID, fetchedLogin, fetchErr := fetchGitHubUserInfo(ctx, token)
	if fetchErr != nil {
		return "", fmt.Errorf("failed to fetch user info from GitHub: %w", fetchErr)
	}

	// Store fetched ID and login for next time
	if errStore := p.keyring.Set(ServiceName, GithubUserID, fetchedUserID); errStore != nil {
		fmt.Printf("Warning: failed to store fetched UserID in keyring: %v\n", errStore)
	}
	if errStore := p.keyring.Set(ServiceName, GithubLogin, fetchedLogin); errStore != nil {
		fmt.Printf("Warning: failed to store fetched Login in keyring: %v\n", errStore)
	}

	return fetchedUserID, nil
}

// GetGithubLogin retrieves the stored GitHub Login.
// It attempts to fetch from GitHub if not found in keyring but a token exists.
func (p *GithubProvider) GetGithubLogin(ctx context.Context) (string, error) {
	login, err := p.keyring.Get(ServiceName, GithubLogin)
	if err == nil && login != "" {
		return login, nil // Found in keyring
	}

	// Not in keyring or error retrieving, try to fetch if token exists
	if !errors.Is(err, oskeyring.ErrNotFound) && err != nil {
		// Some other error with keyring for Login, don't fallback to token fetch for this specific error.
		return "", fmt.Errorf("failed to get Login from keyring: %w", err)
	}

	// Attempt to fetch using token
	token, tokenErr := p.GetToken(ctx)
	if tokenErr != nil {
		return "", fmt.Errorf("cannot fetch Login without token: %w", tokenErr)
	}

	fetchedUserID, fetchedLogin, fetchErr := fetchGitHubUserInfo(ctx, token)
	if fetchErr != nil {
		return "", fmt.Errorf("failed to fetch user info from GitHub: %w", fetchErr)
	}

	// Store fetched ID and login for next time (UserID might be redundant if GetUserID was called first, but Set is idempotent)
	if errStore := p.keyring.Set(ServiceName, GithubUserID, fetchedUserID); errStore != nil {
		fmt.Printf("Warning: failed to store fetched UserID in keyring: %v\n", errStore)
	}
	if errStore := p.keyring.Set(ServiceName, GithubLogin, fetchedLogin); errStore != nil {
		fmt.Printf("Warning: failed to store fetched Login in keyring: %v\n", errStore)
	}

	return fetchedLogin, nil
}

// Logout removes the stored GitHub token and user identifiers using the injected KeyringService.
func (p *GithubProvider) Logout(ctx context.Context) error {
	tokenErr := p.keyring.Delete(ServiceName, GithubToken)
	userIDErr := p.keyring.Delete(ServiceName, GithubUserID)
	loginErr := p.keyring.Delete(ServiceName, GithubLogin)

	var combinedErr error
	if tokenErr != nil && !errors.Is(tokenErr, oskeyring.ErrNotFound) {
		combinedErr = fmt.Errorf("failed to delete token from keyring: %w", tokenErr)
	}
	if userIDErr != nil && !errors.Is(userIDErr, oskeyring.ErrNotFound) {
		userIdErrMsg := fmt.Sprintf("failed to delete UserID from keyring: %v", userIDErr)
		if combinedErr == nil {
			combinedErr = errors.New(userIdErrMsg)
		} else {
			combinedErr = fmt.Errorf("%w; %s", combinedErr, userIdErrMsg)
		}
	}
	if loginErr != nil && !errors.Is(loginErr, oskeyring.ErrNotFound) {
		loginErrMsg := fmt.Sprintf("failed to delete Login from keyring: %v", loginErr)
		if combinedErr == nil {
			combinedErr = errors.New(loginErrMsg)
		} else {
			combinedErr = fmt.Errorf("%w; %s", combinedErr, loginErrMsg)
		}
	}

	if combinedErr != nil {
		return combinedErr
	}

	fmt.Println("Successfully logged out and removed token and user identifiers.")
	return nil
}

// Ensure GithubProvider implements Provider interface
var _ Provider = (*GithubProvider)(nil)
