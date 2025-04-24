package commands

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"github.com/mscno/esec/pkg/projectfile"
)

type UnshareCmd struct {
	KeyName   string   `arg:"" help:"Key to unshare (e.g. ESEC_PRIVATE_KEY_PROD)"`
	Users     []string `help:"Comma-separated GitHub usernames or IDs to unshare from" name:"users" sep:","`
	ServerURL string   `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string   `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *UnshareCmd) Run(_ *kong.Context) error {
	if c.KeyName == "" || len(c.Users) == 0 {
		return fmt.Errorf("must provide key name and at least one user to unshare")
	}
	orgRepo, err := projectfile.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client := client.NewConnectClient(client.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	ctx := context.Background()
	perUserPayload, err := client.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull current sharing state: %w", err)
	}
	// Remove specified users from the key's recipients
	if blobs, ok := perUserPayload[c.KeyName]; ok {
		for _, user := range c.Users {
			delete(blobs, user)
		}
		perUserPayload[c.KeyName] = blobs
	} else {
		return fmt.Errorf("no such key shared: %s", c.KeyName)
	}
	// Push updated sharing state
	if err := client.PushKeysPerUser(ctx, orgRepo, perUserPayload); err != nil {
		return fmt.Errorf("failed to update sharing state: %w", err)
	}
	fmt.Printf("Unshared %s from users: %v\n", c.KeyName, c.Users)
	return nil
}
