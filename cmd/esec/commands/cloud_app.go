package commands

import "fmt"

type AppCmd struct {
	Check AppCheckInstallationCmd `cmd:"check" help:"Check GitHub App installation status."`
}

type AppCheckInstallationCmd struct {
	Org  string `optional:"" short:"o" help:"GitHub organization name to check."`
	Repo string `optional:"" short:"r" help:"GitHub repository name to check (format: owner/repo)."`
}

func (c *AppCheckInstallationCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	if c.Org == "" && c.Repo == "" {
		return fmt.Errorf("either --org or --repo must be specified")
	}
	if c.Org != "" && c.Repo != "" {
		return fmt.Errorf("only one of --org or --repo can be specified")
	}

	connectClient, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	var targetName string
	var isOrg bool
	if c.Org != "" {
		targetName = c.Org
		isOrg = true
		ctx.Logger.Info("Checking GitHub App installation status", "organization", targetName)
	} else {
		targetName = c.Repo
		isOrg = false
		ctx.Logger.Info("Checking GitHub App installation status", "repository", targetName)
	}

	installed, instID, msg, err := connectClient.CheckInstallation(ctx, targetName, isOrg)
	if err != nil {
		ctx.Logger.Error("Failed to check installation status", "error", err)
		return fmt.Errorf("could not check installation status: %w", err)
	}

	fmt.Printf("Installation Status for %s:\n", targetName)
	fmt.Printf("  Installed: %t\n", installed)
	if installed && instID != "" {
		fmt.Printf("  Installation ID: %s\n", instID)
	}
	if msg != "" {
		fmt.Printf("  Message: %s\n", msg)
	}
	return nil
}
