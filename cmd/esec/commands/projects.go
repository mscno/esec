package commands

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"github.com/mscno/esec/pkg/projectfile"
)

type ProjectsCmd struct {
	Create ProjectsCreateCmd `cmd:"" help:"Create a project on the sync server"`
	Info   ProjectsInfoCmd   `cmd:"" help:"Show info (secrets) for a project from the sync server"`
}

type ProjectsCreateCmd struct {
	OrgRepo   string `arg:"" name:"org/repo" help:"GitHub repository identifier (e.g., 'my-org/my-repo')."`
	ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *ProjectsCreateCmd) Run(_ *kong.Context) error {
	if c.OrgRepo == "" {
		return fmt.Errorf("missing required argument: org/repo")
	}
	// Check if a valid .esec-project file already exists in the current directory
	if _, err := projectfile.ReadProjectFile("."); err == nil {
		return fmt.Errorf(".esec-project file already exists and is valid")
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
	client := client.NewConnectClient(client.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})

	ctx := context.Background()
	err := client.CreateProject(ctx, c.OrgRepo)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	// Write the new project file after successful creation
	if err := projectfile.WriteProjectFile(".", c.OrgRepo); err != nil {
		return fmt.Errorf("project created, but failed to write .esec-project file: %w", err)
	}
	fmt.Printf("Successfully created project '%s' on %s\n", c.OrgRepo, c.ServerURL)
	return nil
}

type ProjectsInfoCmd struct {
	OrgRepo   string `arg:"" name:"org/repo" help:"GitHub repository identifier (e.g., 'my-org/my-repo')."`
	ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *ProjectsInfoCmd) Run(_ *kong.Context) error {
	if c.OrgRepo == "" {
		return fmt.Errorf("missing required argument: org/repo")
	}
	// Retrieve token from keyring if not provided
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required for project info (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client := client.NewConnectClient(client.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	ctx := context.Background()
	secrets, err := client.PullKeysPerUser(ctx, c.OrgRepo)
	if err != nil {
		return fmt.Errorf("failed to fetch project info: %w", err)
	}
	if len(secrets) == 0 {
		fmt.Println("No secrets found for project.")
		return nil
	}
	fmt.Printf("Secrets for %s:\n", c.OrgRepo)
	for k, v := range secrets {
		fmt.Printf("%s=%s\n", k, v)
	}
	return nil
}
