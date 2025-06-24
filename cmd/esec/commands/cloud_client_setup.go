package commands

import (
	"errors"
	"fmt"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"github.com/mscno/esec/pkg/oskeyring"
	"strconv"
	"time"
)

func setupConnectClient(ctx *cliCtx, cloudCmd *CloudCmd) (*client.ConnectClient, error) {
	serverURLFlag := cloudCmd.ServerURL
	var sessionToken string
	var err error

	// Prefer explicit token if provided via flag/env
	if cloudCmd.AuthToken != "" {
		sessionToken = cloudCmd.AuthToken
		ctx.Logger.Debug("Using session token from command line flag or ESEC_AUTH_TOKEN env var.")
	} else {
		// Retrieve app session token from keyring
		sessionToken, err = ctx.OSKeyring.Get(auth.ServiceName, AppSessionTokenKey)
		if err != nil {
			if errors.Is(err, oskeyring.ErrNotFound) {
				return nil, fmt.Errorf("app session token not found in keyring. Please login first with 'esec cloud auth login'")
			}
			return nil, fmt.Errorf("failed to get app session token from keyring: %w", err)
		}
		if sessionToken == "" { // Should be covered by ErrNotFound, but defensive check
			return nil, fmt.Errorf("app session token not found in keyring (empty). Please login first with 'esec cloud auth login'")
		}
		ctx.Logger.Debug("Using app session token from OS keyring.")

		// Optional: Check token expiry if stored (basic check)
		expiryStr, expiryErr := ctx.OSKeyring.Get(auth.ServiceName, AppSessionExpiryKey)
		if expiryErr == nil {
			expiryUnix, parseErr := strconv.ParseInt(expiryStr, 10, 64)
			if parseErr == nil && time.Now().Unix() > expiryUnix {
				// Token is likely expired, prompt for re-login
				_ = ctx.OSKeyring.Delete(auth.ServiceName, AppSessionTokenKey) // Clean up
				_ = ctx.OSKeyring.Delete(auth.ServiceName, AppSessionExpiryKey)
				return nil, fmt.Errorf("app session token has expired. Please login again with 'esec cloud auth login'")
			}
		}
	}

	ctx.Logger.Debug("Initializing ConnectClient", "serverURL", serverURLFlag)
	connectClient := client.NewConnectClient(client.ClientConfig{
		ServerURL: serverURLFlag,
		AuthToken: sessionToken, // This is now the app-managed session token
		Logger:    ctx.Logger,
	})

	return connectClient, nil
}
