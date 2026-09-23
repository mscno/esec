// Package commands implements the CLI commands for the esec tool.
package commands

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/fileutils"
)

type cliCtx struct {
	Logger *slog.Logger
	Quiet  bool
}

// ExitError is returned by commands that need to terminate the process with a
// specific exit code, e.g. to propagate the exit code of a child process.
type ExitError struct {
	Code int
}

// Error implements the error interface.
func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

type cli struct {
	Keygen  KeygenCmd  `cmd:"" help:"Generate a new keypair"`
	Encrypt EncryptCmd `cmd:"" help:"Encrypt a secrets file in place"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt a secrets file to stdout"`
	Get     GetCmd     `cmd:"" help:"Decrypt a secrets file and print a single value"`
	Run     RunCmd     `cmd:"" help:"Run a command with decrypted secrets as environment variables"`

	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug logging" env:"ESEC_DEBUG"`
	Quiet   bool             `help:"Suppress non-essential output" short:"q"`
}

// Execute runs the CLI with the given version string.
func Execute(version string) {
	// Git-style subcommand passthrough: `esec <x>` runs `esec-<x>` from PATH
	// when <x> is not a builtin command (e.g. `esec vault` → `esec-vault`).
	if code, handled := maybeExecExternal(os.Args); handled {
		os.Exit(code)
	}

	var cli cli
	ctx := kong.Parse(&cli,
		kong.ShortUsageOnError(),
		kong.Name("esec"),
		kong.Description("esec encrypts and decrypts secrets files using public-key cryptography"),
		kong.Vars{"version": version},
	)

	// Setup logger with appropriate level based on debug flag
	logLevel := slog.LevelInfo
	if cli.Debug {
		logLevel = slog.LevelDebug
	}

	// Create logger with handler that respects the level.
	// Logs go to stderr so stdout stays clean for piping.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	// Make the library package log through the same handler.
	slog.SetDefault(logger)

	err := ctx.Run(&cliCtx{Logger: logger, Quiet: cli.Quiet})

	// Commands may request a specific process exit code (e.g. `run` forwarding
	// the exit code of its child process).
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	ctx.FatalIfErrorf(err)
}

// writeData writes data to w, ensuring the output ends with exactly one
// trailing newline so it displays cleanly on a terminal.
func writeData(w io.Writer, data []byte) error {
	if _, err := w.Write(data); err != nil {
		return err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		_, err := io.WriteString(w, "\n")
		return err
	}
	return nil
}

func processFileOrEnv(input string, defaultFileFormat fileutils.FileFormat) (filename string, err error) {
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
	// Validate environment string: dot-separated lowercase alphanumeric
	// segments (e.g. "dev" or "registry.production" for monorepo components).
	// The empty environment selects the default file (e.g. ".ejson").
	for _, segment := range strings.Split(environment, ".") {
		if segment == "" && environment != "" {
			return "", fmt.Errorf("invalid environment name: %s - should be dot-separated lowercase alphanumeric segments", input)
		}
		for _, char := range segment {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", char) {
				return "", fmt.Errorf("invalid environment name: %s - should be dot-separated lowercase alphanumeric segments", input)
			}
		}
	}
	if strings.ContainsAny(environment, "\\/") {
		return "", fmt.Errorf("invalid environment name: %s - should be dot-separated lowercase alphanumeric segments", input)
	}

	// Generate filename using the default format (.env)
	filename = fileutils.GenerateFilename(defaultFileFormat, environment)
	return path.Clean(filename), nil
}
