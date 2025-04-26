package commands

import (
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/oskeyring"

	"log/slog"
	"os"
	"path"
	"strings"
)

type cliCtx struct {
	Logger *slog.Logger
	context.Context
	OSKeyring oskeyring.Service
}

type cli struct {
	Keygen  KeygenCmd  `cmd:"" help:"Generate key"`
	Encrypt EncryptCmd `cmd:"" help:"Encrypt a secret"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt a secret"`
	Get     GetCmd     `cmd:"" help:"Decrypt a secret and extract a specific key"`
	Run     RunCmd     `cmd:"" help:"Decrypt a secret, set environment variables, and run a command"`

	// Cloud commands grouped under 'cloud'
	Cloud CloudCmd `cmd:"cloud" help:"Commands interacting with the cloud sync server"`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug mode"`
}

type CloudCmd struct {
	// Global flags for cloud commands (inherited by subcommands)
	ServerURL  string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080" group:"Cloud Flags:"`
	AuthToken  string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN" group:"Cloud Flags:"`
	ProjectDir string `help:"Directory containing the projects file" env:"ESEC_PROJECTS_FILE_DIR" default:"." group:"Cloud Flags:"`

	// Cloud subcommands
	Auth     AuthCmd     `cmd:"" help:"Authentication commands"`
	Sync     SyncCmd     `cmd:"" help:"Sync commands"`
	Share    ShareCmd    `cmd:"" help:"Share a secret key with other users"`
	Unshare  UnshareCmd  `cmd:"" help:"Unshare a secret key with other users"`
	Projects ProjectsCmd `cmd:"" help:"Project commands"`
	Keys     KeysCmd     `cmd:"" help:"Key management commands"`
}

func Execute(version string) {
	var cli cli
	ctx := kong.Parse(&cli,
		kong.ShortUsageOnError(),
		kong.Name("esec"),
		kong.Description("esec is a tool for encrypting secrets"),
		kong.Vars{"version": version},
	)

	// Setup logger with appropriate level based on debug flag
	logLevel := slog.LevelInfo
	if cli.Debug {
		logLevel = slog.LevelDebug
	}

	// Create logger with handler that respects the level
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Instantiate the OS keyring service
	keyringSvc := oskeyring.NewDefaultService()

	err := ctx.Run(&cliCtx{Context: context.Background(), Logger: logger, OSKeyring: keyringSvc})
	ctx.FatalIfErrorf(err)
}

func processFileOrEnv(input string, defaultFileFormat fileutils.FileFormat) (filename string, err error) {
	// This is a helper function, so we can't use the context logger directly
	// Debug logs for this function will be handled by the calling functions

	// Check if input starts with any valid format
	isFile := false
	for _, format := range fileutils.ValidFormats() {
		if strings.Contains(path.Base(input), string(format)) {
			isFile = true
			break
		}
	}

	if isFile {
		return input, nil
	}

	// Input is treated as an environment
	environment := input
	// Validate environment string
	if strings.ContainsAny(environment, ".\\/") {
		return "", fmt.Errorf("invalid environment name: %s - should not contain dots or path separators", input)
	}

	for _, char := range environment {
		if !strings.Contains("abcdefghijklmnopqrstuvwxyz0123456789", string(char)) {
			return "", fmt.Errorf("invalid environment name: %s - should be lowercase alphanumeric", input)
		}
	}

	// Generate filename using the default format (.env)
	filename = fileutils.GenerateFilename(defaultFileFormat, environment)
	return path.Clean(filename), nil
}
