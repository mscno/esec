package commands

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mscno/esec/pkg/auth"
)

type AuthCmd struct {
	Login           LoginCmd               `cmd:"" help:"Authenticate with GitHub using device flow."`
	Logout          LogoutCmd              `cmd:"" help:"Remove stored authentication credentials."`
	Sync            AuthSyncCmd            `cmd:"" help:"Register with the sync server."`
	Info            AuthInfoCmd            `cmd:"" help:"Show info about the currently logged-in user."`
	GenerateKeypair AuthGenerateKeypairCmd `cmd:"" help:"Generate a new keypair and print a BIP-39 recovery phrase"`
	RecoverKeypair  AuthRecoverKeypairCmd  `cmd:"" help:"Recover your keypair from a 24-word BIP39 mnemonic phrase"`

	// Global flags for auth commands
	GithubClientID string `env:"ESEC_GITHUB_CLIENT_ID" default:"Iv23liDPymlwvV4Z7ROm" help:"GitHub OAuth App Client ID." short:"c"`
}

type LoginCmd struct{}

func (c *LoginCmd) Run(ctx *cliCtx, parent *AuthCmd) error {
	// --- Existing login logic ---
	if parent.GithubClientID == "" {
		return fmt.Errorf("GitHub Client ID must be provided via --github-client-id flag or ESEC_GITHUB_CLIENT_ID env var")
	}

	authCfg := auth.Config{
		GithubClientID: parent.GithubClientID,
	}
	provider := auth.NewGithubProvider(authCfg, ctx.OSKeyring)

	ctx.Logger.Info("Starting GitHub device login flow...")
	err := provider.Login(ctx)
	if err != nil {
		ctx.Logger.Error("Authentication failed", "error", err)
		return fmt.Errorf("authentication failed: %w", err)
	}
	ctx.Logger.Info("Authentication successful.")

	return nil
}

type AuthSyncCmd struct {
	// ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"` // Removed
	// AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"` // Removed
}

func (c *AuthSyncCmd) Run(ctx *cliCtx, parent *AuthCmd, cloud *CloudCmd) error {
	// Load public key from keyring using the injected service
	pubKey, err := ctx.OSKeyring.Get("esec", "public-key")
	if err != nil {
		return fmt.Errorf("No public key found in keyring. Please run 'esec auth generate-keypair' before logging in.")
	}

	// Setup client, retrieving token if necessary via the helper
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Registering user and public key with server...")
	err = connectClient.SyncUser(ctx, pubKey)
	if err != nil {
		ctx.Logger.Error("Registration failed", "error", err)
		return fmt.Errorf("registration failed: %w", err)
	}
	ctx.Logger.Info("User and public key registered with server.")

	// (Key pinning removed: do not pin own key on login)
	return nil
}

type LogoutCmd struct{}

func (c *LogoutCmd) Run(ctx *cliCtx, parent *AuthCmd) error {
	// Note: Logout doesn't strictly need the client ID, but provider creation might.
	// We instantiate it similarly for consistency, even if cfg is empty here.
	authCfg := auth.Config{}
	provider := auth.NewGithubProvider(authCfg, ctx.OSKeyring)

	ctx.Logger.Info("Logging out and removing stored token...")
	err := provider.Logout(ctx)
	if err != nil {
		ctx.Logger.Error("Logout failed", "error", err)
		return fmt.Errorf("logout failed: %w", err)
	}
	ctx.Logger.Info("Logout successful.")
	return nil
}

type AuthInfoCmd struct{}

type githubUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    int    `json:"id"`
}

func (c *AuthInfoCmd) Run(ctx *cliCtx, parent *AuthCmd, cloud *CloudCmd) error {
	authCfg := auth.Config{GithubClientID: parent.GithubClientID}
	provider := auth.NewGithubProvider(authCfg, ctx.OSKeyring)
	token, err := provider.GetToken(ctx)
	if err != nil || token == "" {
		ctx.Logger.Error("No authentication token found. Please login first.")
		return fmt.Errorf("no authentication token found: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		ctx.Logger.Error("Failed to fetch user info from GitHub", "status", resp.Status)
		return fmt.Errorf("failed to fetch user info from GitHub: %s", resp.Status)
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return fmt.Errorf("failed to decode GitHub user info: %w", err)
	}

	fmt.Printf("GitHub User Info:\n")
	fmt.Printf("  Login: %s\n", user.Login)
	fmt.Printf("  Name:  %s\n", user.Name)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  ID:    %d\n", user.ID)
	return nil
}
