package commands

import (
	"errors"
	"fmt"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"github.com/mscno/esec/pkg/oskeyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const AppSessionTokenKey = "app_session_token"   // New keyring key for the app session token
const AppSessionExpiryKey = "app_session_expiry" // Key for storing expiry

type AuthCmd struct {
	Login           LoginCmd               `cmd:"" help:"Authenticate with GitHub and obtain an app session."`
	Logout          LogoutCmd              `cmd:"" help:"Remove stored session credentials."`
	Sync            AuthSyncCmd            `cmd:"" help:"Register with the sync server (requires login)."`
	Info            AuthInfoCmd            `cmd:"" help:"Show info about the currently logged-in user (via session)."`
	GenerateKeypair AuthGenerateKeypairCmd `cmd:"" help:"Generate a new keypair and print a BIP-39 recovery phrase"`
	RecoverKeypair  AuthRecoverKeypairCmd  `cmd:"" help:"Recover your keypair from a 24-word BIP39 mnemonic phrase"`

	GithubClientID string `env:"ESEC_GITHUB_CLIENT_ID" default:"Iv23liDPymlwvV4Z7ROm" help:"GitHub OAuth App Client ID." short:"c"`
}

type LoginCmd struct{}

func (c *LoginCmd) Run(ctx *cliCtx, parent *AuthCmd, cloudCmd *CloudCmd) error { // Added cloudCmd
	if parent.GithubClientID == "" {
		return fmt.Errorf("GitHub Client ID must be provided via --github-client-id flag or ESEC_GITHUB_CLIENT_ID env var")
	}

	authCfg := auth.Config{
		GithubClientID: parent.GithubClientID,
	}
	// Step 1: GitHub Device Flow to get GitHub User Token
	// We use a temporary GithubProvider instance here just for the device flow part.
	// The token it stores internally isn't the one we'll use long-term.
	tempKeyring := auth.NewGithubProvider(authCfg, ctx.OSKeyring) // Can use the real OSKeyring for temp storage too

	ctx.Logger.Info("Starting GitHub device login flow...")
	// The Login method of GithubProvider needs to be adapted or we do it manually here.
	// For now, let's assume provider.Login() successfully gets and *temporarily stores* the GitHub token.
	// Or, more directly:
	githubUserToken, err := auth.PerformDeviceFlow(ctx, oauthConfig(parent.GithubClientID)) // oauthConfig needs to be a helper
	if err != nil {
		ctx.Logger.Error("GitHub device flow failed", "error", err)
		return fmt.Errorf("GitHub authentication failed: %w", err)
	}
	ctx.Logger.Info("GitHub device flow successful. Requesting app session...")

	// Step 2: Exchange GitHub User Token for App Session Token
	// Create a temporary client *without* an auth token to call InitiateSession
	tempClientCfg := client.ClientConfig{
		ServerURL: cloudCmd.ServerURL, // Get ServerURL from CloudCmd
		AuthToken: "",                 // No token for this specific call
		Logger:    ctx.Logger,
	}
	tempConnectClient := client.NewConnectClient(tempClientCfg)

	sessionToken, expiresAt, err := tempConnectClient.InitiateSession(ctx, githubUserToken)
	if err != nil {
		ctx.Logger.Error("Failed to initiate app session", "error", err)
		return fmt.Errorf("failed to obtain app session: %w", err)
	}

	// Step 3: Store App Session Token in OS Keyring
	if err := ctx.OSKeyring.Set(auth.ServiceName, AppSessionTokenKey, sessionToken); err != nil {
		return fmt.Errorf("failed to store app session token in keyring: %w", err)
	}
	if err := ctx.OSKeyring.Set(auth.ServiceName, AppSessionExpiryKey, fmt.Sprintf("%d", expiresAt)); err != nil {
		// Log but don't fail login if expiry can't be stored
		ctx.Logger.Warn("Failed to store session expiry in keyring", "error", err)
	}

	// Optionally, remove the GitHub user token from keyring if it was stored by PerformDeviceFlow
	_ = ctx.OSKeyring.Delete(auth.ServiceName, auth.GithubToken)

	// Fetch user info using the new session to store GitHub ID and Login
	// This ensures they are stored after a successful session is established.
	// Create a client configured with the new session token for the GetUserPublicKey call (or a new /userinfo endpoint)
	finalClientCfg := client.ClientConfig{
		ServerURL: cloudCmd.ServerURL,
		AuthToken: sessionToken, // Use the new session token
		Logger:    ctx.Logger,
	}
	finalConnectClient := client.NewConnectClient(finalClientCfg)

	// We need the user's own ID and login. The server knows this from the session.
	// A GetSelfUserPublicKey or similar endpoint would be ideal.
	// For now, let's assume InitiateSession response could include UserID and Login,
	// or we make a subsequent call.
	// Let's assume the server's RegisterUser (called by AuthSyncCmd) will handle storing user details
	// if they are not already present, using the info from the app session.

	ctx.Logger.Info("App session obtained and stored successfully.")
	fmt.Println("Login successful. Your session is now active.")
	fmt.Printf("To complete setup, run: esec cloud auth sync\n")

	return nil
}

// Helper for OAuth config, similar to what's in pkg/auth/github.go
func oauthConfig(clientID string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: clientID,
		Scopes:   []string{"repo", "read:user"}, // read:user to get user ID/login
		Endpoint: github.Endpoint,
	}
}

type AuthSyncCmd struct{}

func (c *AuthSyncCmd) Run(ctx *cliCtx, parent *AuthCmd, cloud *CloudCmd) error {
	pubKey, err := ctx.OSKeyring.Get("esec", "public-key")
	if err != nil {
		return fmt.Errorf("no public key found in keyring. Please run 'esec cloud auth generate-keypair' first")
	}

	// setupConnectClient will now use the app session token
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Registering user and public key with server (using app session)...")
	err = connectClient.SyncUser(ctx, pubKey) // SyncUser on server uses user from app session
	if err != nil {
		ctx.Logger.Error("Registration failed", "error", err)
		return fmt.Errorf("registration failed: %w", err)
	}
	ctx.Logger.Info("User and public key registered/updated with server.")
	return nil
}

type LogoutCmd struct{}

func (c *LogoutCmd) Run(ctx *cliCtx, parent *AuthCmd) error {
	ctx.Logger.Info("Logging out and removing stored session token...")
	errToken := ctx.OSKeyring.Delete(auth.ServiceName, AppSessionTokenKey)
	errExpiry := ctx.OSKeyring.Delete(auth.ServiceName, AppSessionExpiryKey)
	// Also remove old GitHub token/user ID if they exist from previous versions
	_ = ctx.OSKeyring.Delete(auth.ServiceName, auth.GithubToken)
	_ = ctx.OSKeyring.Delete(auth.ServiceName, auth.GithubUserID)
	_ = ctx.OSKeyring.Delete(auth.ServiceName, auth.GithubLogin)

	if errToken != nil && !errors.Is(errToken, oskeyring.ErrNotFound) {
		ctx.Logger.Error("Failed to delete session token from keyring", "error", errToken)
		// Continue to delete other keys
	}
	if errExpiry != nil && !errors.Is(errExpiry, oskeyring.ErrNotFound) {
		ctx.Logger.Error("Failed to delete session expiry from keyring", "error", errExpiry)
	}

	if (errToken != nil && !errors.Is(errToken, oskeyring.ErrNotFound)) ||
		(errExpiry != nil && !errors.Is(errExpiry, oskeyring.ErrNotFound)) {
		return fmt.Errorf("logout partially failed; please check logs")
	}

	ctx.Logger.Info("Logout successful. Stored session credentials removed.")
	return nil
}

type AuthInfoCmd struct{}

// AuthInfoCmd now shows info based on the app session, potentially calling a server endpoint.
// For simplicity, it could just confirm a session token exists.
// A more advanced version would call a server endpoint like `/me` to get user details from session.
func (c *AuthInfoCmd) Run(ctx *cliCtx, parent *AuthCmd, cloud *CloudCmd) error {
	sessionToken, err := ctx.OSKeyring.Get(auth.ServiceName, AppSessionTokenKey)
	if err != nil || sessionToken == "" {
		ctx.Logger.Error("No active session found. Please login first with 'esec cloud auth login'.")
		return fmt.Errorf("not logged in: %w", err)
	}

	// Validate token locally (optional, server will do it anyway on next call)
	// claims, err := session.ValidateToken(sessionToken) // This requires session pkg to be accessible or a helper
	// if err != nil {
	// 	_ = ctx.OSKeyring.Delete(auth.ServiceName, AppSessionTokenKey) // Clean up invalid token
	// 	_ = ctx.OSKeyring.Delete(auth.ServiceName, AppSessionExpiryKey)
	// 	return fmt.Errorf("invalid or expired session token, please login again: %w", err)
	// }
	// fmt.Printf("App Session Active for GitHub User:\n  Login: %s\n  ID:    %s\n", claims.GithubLogin, claims.GithubUserID)

	// For a more robust check, call a lightweight authenticated endpoint on the server
	// e.g., GetUserPublicKey for self.
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return fmt.Errorf("could not initialize client: %w", err)
	}

	// To get self ID/Login, we need to retrieve them if stored, or make a call.
	// Let's assume they are NOT reliably in keyring for this command.
	// A dedicated "/me" endpoint on the server would be best.
	// As a proxy, we can try GetUserPublicKey with a placeholder if we don't know our ID.
	// This is a bit of a hack. A /me endpoint is better.
	// For now, just confirm token exists and is somewhat parsable.
	// The server will ultimately validate it.

	// Try to get self public key as a way to verify session (and get user info)
	// This requires user to have run `auth sync` first.
	// A better approach: a dedicated `/auth/me` endpoint on the server that returns user info from session.
	// For now, let's just state that a session token exists.
	fmt.Println("An active esec session token is present in the keyring.")
	fmt.Println("Run 'esec cloud auth sync' to ensure your public key is registered with the server.")

	// If you had a /me endpoint:
	// userInfo, err := connectClient.GetMe(ctx) // Hypothetical GetMe
	// if err != nil {
	// 	return fmt.Errorf("failed to get user info from server: %w", err)
	// }
	// fmt.Printf("Session active for: %s (ID: %s)\n", userInfo.Login, userInfo.ID)

	return nil
}
