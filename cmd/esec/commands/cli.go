// Package commands implements the CLI commands for the esec tool.
package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/fileutils"
)

type cliCtx struct {
	Logger *slog.Logger
	Ctx    context.Context //nolint:containedctx // CLI context needs to pass context to subcommands
}

type cli struct {
	Keygen  KeygenCmd  `cmd:"" help:"Generate key"`
	Encrypt EncryptCmd `cmd:"" help:"Encrypt a secret"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt a secret"`
	Get     GetCmd     `cmd:"" help:"Decrypt a secret and extract a specific key"`
	Run     RunCmd     `cmd:"" help:"Decrypt a secret, set environment variables, and run a command"`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug mode"`
}

// Execute runs the CLI with the given version string.
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

	err := ctx.Run(&cliCtx{Ctx: context.Background(), Logger: logger})
	ctx.FatalIfErrorf(err)
}

func processFileOrEnv(input string, defaultFileFormat fileutils.FileFormat) (filename string, err error) {
	// This is a helper function, so we can't use the context logger directly
	// Debug logs for this function will be handled by the calling functions

	// Check if input is a file path (contains path separator) or starts with a valid format
	baseName := path.Base(input)
	isFile := false

	// If input contains a path separator, treat it as a file path
	if strings.Contains(input, "/") || strings.Contains(input, string(os.PathSeparator)) {
		// It's a path - check if basename starts with a valid format
		for _, format := range fileutils.ValidFormats() {
			if strings.HasPrefix(baseName, string(format)) {
				isFile = true
				break
			}
		}
	} else {
		// No path separator - check for format prefix with proper suffix validation
		// This prevents "my.env.backup" from matching as ".env"
		for _, format := range fileutils.ValidFormats() {
			formatStr := string(format)
			if strings.HasPrefix(baseName, formatStr) {
				remainder := strings.TrimPrefix(baseName, formatStr)
				// Valid if nothing follows or if it's followed by a dot (e.g., ".env.dev")
				if remainder == "" || strings.HasPrefix(remainder, ".") {
					isFile = true
					break
				}
			}
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
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", char) {
			return "", fmt.Errorf("invalid environment name: %s - should be lowercase alphanumeric", input)
		}
	}

	// Generate filename using the default format (.env)
	filename = fileutils.GenerateFilename(defaultFileFormat, environment)
	return path.Clean(filename), nil
}
