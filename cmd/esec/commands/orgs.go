package commands

import (
	"fmt"
	// TODO: Add imports for tablewriter if used for list
)

// OrgsCmd is the parent command for organization operations.
type OrgsCmd struct {
	Create OrgsCreateCmd `cmd:"" help:"Create a new team organization."`
	List   OrgsListCmd   `cmd:"list" help:"List organizations you own."`
	Delete OrgsDeleteCmd `cmd:"delete" help:"Delete a team organization you own."`
	// Get    OrgsGetCmd    `cmd:"get" help:"Get details for a specific organization."` // Add later if needed
}

type OrgsCreateCmd struct {
	Name string `arg:"" required:"" help:"Name for the new team organization."`
}

type OrgsListCmd struct {
	// No arguments currently
}

type OrgsDeleteCmd struct {
	ID string `arg:"" required:"" help:"ID of the team organization to delete."`
}

// Run executes the create organization command.
func (c *OrgsCreateCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	client, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Creating team organization...", "name", c.Name)
	org, err := client.CreateOrganization(ctx, c.Name)
	if err != nil {
		ctx.Logger.Error("Failed to create organization", "name", c.Name, "error", err)
		return fmt.Errorf("failed to create organization: %w", err)
	}

	fmt.Printf("Successfully created team organization:\n")
	fmt.Printf("  ID:   %s\n", org.Id)
	fmt.Printf("  Name: %s\n", org.Name)
	fmt.Printf("  Type: %s\n", org.Type)
	// fmt.Printf("  Owner: %s\n", org.OwnerGithubId) // Owner info might be implicit
	return nil
}

// Run executes the list organizations command.
func (c *OrgsListCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	client, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Listing organizations...")
	orgs, err := client.ListOrganizations(ctx)
	if err != nil {
		ctx.Logger.Error("Failed to list organizations", "error", err)
		return fmt.Errorf("failed to list organizations: %w", err)
	}

	if len(orgs) == 0 {
		fmt.Println("No organizations found.")
		return nil
	}

	fmt.Println("Organizations:")
	// TODO: Use a table writer for better formatting
	for _, org := range orgs {
		fmt.Printf("  - ID: %s, Name: %s, Type: %s\n", org.Id, org.Name, org.Type)
	}
	return nil
}

// Run executes the delete organization command.
func (c *OrgsDeleteCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	client, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Deleting organization...", "id", c.ID)
	status, err := client.DeleteOrganization(ctx, c.ID)
	if err != nil {
		ctx.Logger.Error("Failed to delete organization", "id", c.ID, "error", err)
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	fmt.Printf("Status: %s\n", status)
	return nil
}
