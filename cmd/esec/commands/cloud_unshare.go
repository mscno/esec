package commands

import (
	"fmt"
	"github.com/mscno/esec/pkg/client"

	"github.com/mscno/esec/pkg/projectfile"
)

type UnshareCmd struct {
	KeyName client.PrivateKeyName `arg:"" help:"Key to unshare (e.g. ESEC_PRIVATE_KEY_PROD)"`
	Users   []string              `help:"Comma-separated GitHub usernames or IDs to unshare from" name:"users" sep:","`
}

func (c *UnshareCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	if c.KeyName == "" || len(c.Users) == 0 {
		return fmt.Errorf("must provide key name and at least one user to unshare")
	}
	orgRepo, err := projectfile.ReadProjectFile(parent.ProjectDir)
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}

	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	perUserPayload, err := connectClient.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull current sharing state: %w", err)
	}
	// Remove specified users from the key's recipients
	for _, user := range c.Users {
		typedUser := client.UserId(user)
		userBlobs, ok := perUserPayload[typedUser]
		if ok {
			delete(perUserPayload[typedUser], c.KeyName)
		} else {
			return fmt.Errorf("no such key shared: %s", c.KeyName)
		}
		perUserPayload[typedUser] = userBlobs
		//if len(userBlobs) == 0 {
		//	delete(perUserPayload, typedUser)
		//}
	}
	// Push updated sharing state
	if err := connectClient.PushKeysPerUser(ctx, orgRepo, perUserPayload); err != nil {
		return fmt.Errorf("failed to update sharing state: %w", err)
	}
	fmt.Printf("Unshared %s from users: %v\n", c.KeyName, c.Users)
	return nil
}
