package commands

import (
	"fmt"

	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
)

// setupConnectClient handles the common logic of retrieving the auth token (if necessary)
// and initializing the ConnectClient.
// It now takes the cliCtx and the CloudCmd struct containing the global flags.
func setupConnectClient(ctx *cliCtx, cloudCmd *CloudCmd) (*client.ConnectClient, error) {
	authTokenFlag := cloudCmd.AuthToken // Get token from CloudCmd
	serverURLFlag := cloudCmd.ServerURL // Get URL from CloudCmd
	token := authTokenFlag
	var err error

	if token == "" {
		// Initialize keyring service and provider to get the token
		// keyringService := auth.NewDefaultKeyringService() // No longer needed, use ctx.OSKeyring
		// We pass an empty config as ClientID isn't needed for GetToken
		provider := auth.NewGithubProvider(auth.Config{}, ctx.OSKeyring) // Pass ctx.OSKeyring
		token, err = provider.GetToken(ctx)                              // Use ctx directly
		if err != nil {
			// Try to provide specific login instructions based on provider type if possible
			// For now, generic error
			return nil, fmt.Errorf("failed to get auth token from keyring: %w. Please login first with 'esec cloud auth login'", err)
		}
		if token == "" {
			return nil, fmt.Errorf("authentication token not found in keyring. Please login first with 'esec cloud auth login'")
		}
	}

	// Initialize the client
	ctx.Logger.Debug("Initializing ConnectClient", "serverURL", serverURLFlag)
	connectClient := client.NewConnectClient(client.ClientConfig{
		ServerURL: serverURLFlag,
		AuthToken: token,
		Logger:    ctx.Logger,
	})

	return connectClient, nil
}
