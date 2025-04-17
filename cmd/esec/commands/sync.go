package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/dotenv"
	"github.com/mscno/esec/pkg/project"
	"github.com/mscno/esec/pkg/sync"
)

type SyncCmd struct {
	Push SyncPushCmd `cmd:"" help:"Push private keys in .esec-keyring to the server"`
	Pull SyncPullCmd `cmd:"" help:"Pull private keys from the server into .esec-keyring"`
}

type SyncPushCmd struct {
	ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}
type SyncPullCmd struct {
	ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *SyncPushCmd) Run(_ *kong.Context) error {
	// Read org/repo from .esec-project
	orgRepo, err := project.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	// Retrieve token from keyring if not provided
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required for CreateProject (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client, err := sync.NewAPIClient(sync.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	if err != nil {
		return fmt.Errorf("failed to create sync client: %w", err)
	}

	keyringPath := ".esec-keyring"
	f, err := os.Open(keyringPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", keyringPath, err)
	}
	defer f.Close()
	envs, err := godotenv.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", keyringPath, err)
	}
	privateKeys := map[string]string{}
	for k, v := range envs {
		if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			privateKeys[k] = v
		}
	}

	ctx := context.Background()
	if err := client.PushKeys(ctx, orgRepo, privateKeys); err != nil {
		return fmt.Errorf("failed to push secrets: %w", err)
	}
	fmt.Println("Pushed private keys to server.")
	return nil
}

func (c *SyncPullCmd) Run(_ *kong.Context) error {
	keyringPath := ".esec-keyring"
	// Read org/repo from .esec-project
	orgRepo, err := project.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	// Retrieve token from keyring if not provided
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required for CreateProject (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client, err := sync.NewAPIClient(sync.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	if err != nil {
		return fmt.Errorf("failed to create sync client: %w", err)
	}
	ctx := context.Background()
	serverKeys, err := client.PullKeys(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull secrets: %w", err)
	}

	// Read local file to preserve ESEC_ACTIVE_KEY/ESEC_ACTIVE_ENVIRONMENT
	existing := map[string]string{}
	lines := map[string]string{}
	f, err := os.Open(keyringPath)
	if err == nil {
		envs, _ := godotenv.Parse(f)
		f.Close()
		for k, v := range envs {
			existing[k] = v
			if k == "ESEC_ACTIVE_KEY" || k == "ESEC_ACTIVE_ENVIRONMENT" {
				lines[k] = v
			}
			if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
				lines[k] = v
			}
		}
	}
	// If any ESEC_PRIVATE_KEY* keys exist locally, prompt for overwrite
	overwrite := true
	for k := range lines {
		if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			var resp string
			fmt.Printf("Local private key %s exists. Overwrite with server value? [y/N]: ", k)
			fmt.Scanln(&resp)
			if strings.ToLower(resp) != "y" {
				overwrite = false
				break
			}
		}
	}
	if !overwrite {
		fmt.Println("Aborted pull: local private keys not overwritten.")
		return nil
	}
	for k, v := range serverKeys {
		if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			lines[k] = v
		}
	}

	// Write new keyring: active keys first, then private keys

	// Only keep active and private keys for writing
	filtered := map[string]string{}
	for k, v := range lines {
		if strings.HasPrefix(k, "ESEC_ACTIVE") || strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			filtered[k] = v
		}
	}
	formatted := dotenv.FormatKeyringFile(filtered)
	if err := os.WriteFile(keyringPath, []byte(formatted), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", keyringPath, err)
	}
	fmt.Println("Pulled private keys from server and updated .esec-keyring.")
	return nil
}
