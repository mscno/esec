package commands

import (
	"fmt"

	"github.com/mscno/esec/pkg/projectfile"
)

type ProjectsCmd struct {
	Create ProjectsCreateCmd `cmd:"" help:"Create a project on the sync server"`
	Info   ProjectsInfoCmd   `cmd:"" help:"Show info (secrets) for a project from the sync server"`
}

type ProjectsCreateCmd struct {
	OrgRepo string `arg:"" name:"org/repo" help:"GitHub repository identifier (e.g., 'my-org/my-repo')."`
}

func (c *ProjectsCreateCmd) Run(ctx *cliCtx, cloud *CloudCmd) error {
	if c.OrgRepo == "" {
		return fmt.Errorf("missing required argument: org/repo")
	}
	// Check if a valid .esec-project file already exists in the current directory
	if _, err := projectfile.ReadProjectFile(cloud.ProjectDir); err == nil {
		return fmt.Errorf(".esec-project file already exists and is valid")
	}

	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err // Error already formatted by helper
	}

	// Use the initialized client
	err = connectClient.CreateProject(ctx, c.OrgRepo)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	// Write the new project file after successful creation
	if err := projectfile.WriteProjectFile(".", c.OrgRepo); err != nil {
		return fmt.Errorf("project created, but failed to write .esec-project file: %w", err)
	}
	fmt.Printf("Successfully created project '%s' on %s\n", c.OrgRepo, cloud.ServerURL)
	return nil
}

type ProjectsInfoCmd struct {
	OrgRepo string `arg:"" name:"org/repo" help:"GitHub repository identifier (e.g., 'my-org/my-repo')."`
}

func (c *ProjectsInfoCmd) Run(ctx *cliCtx, cloud *CloudCmd) error {
	if c.OrgRepo == "" {
		return fmt.Errorf("missing required argument: org/repo")
	}

	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err // Error already formatted by helper
	}

	// Use the initialized client
	secrets, err := connectClient.PullKeysPerUser(ctx, c.OrgRepo)
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
