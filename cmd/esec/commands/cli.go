package commands

import (
	"bytes"
	"context"
	gojson "encoding/json"
	"fmt"
	"io"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"

	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
)

type cliCtx struct {
	Logger *slog.Logger
	context.Context
}

type cli struct {
	Keygen   KeygenCmd        `cmd:"" help:"Generate key"`
	Encrypt  EncryptCmd       `cmd:"" help:"Encrypt a secret"`
	Decrypt  DecryptCmd       `cmd:"" help:"Decrypt a secret"`
	Get      GetCmd           `cmd:"" help:"Decrypt a secret and extract a specific key"`
	Run      RunCmd           `cmd:"" help:"Decrypt a secret, set environment variables, and run a command"`
	Auth     AuthCmd          `cmd:"" help:"Authentication commands"`
	Sync     SyncCmd          `cmd:"" help:"Sync commands"`
	Share    ShareCmd         `cmd:"" help:"Share a secret key with additional users"`
	Keys     KeysCmd          `cmd:"" help:"Key management commands"`
	Projects ProjectsCmd      `cmd:"" help:"Project commands"`
	Version  kong.VersionFlag `help:"Show version"`
	Debug    bool             `help:"Enable debug mode"`
}

func Execute(version string) {
	var cli cli
	ctx := kong.Parse(&cli,
		kong.UsageOnError(),
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

	err := ctx.Run(&cliCtx{Context: context.Background(), Logger: logger})
	ctx.FatalIfErrorf(err)
}

type KeygenCmd struct {
}

func (c *KeygenCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("generating new keypair")

	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		ctx.Logger.Debug("keypair generation failed", "error", err)
		return err
	}

	ctx.Logger.Debug("keypair generated successfully")
	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}

type EncryptCmd struct {
	File   string `arg:"" help:"File or Environment to encrypt" default:""`
	Format string `help:"File format" default:".ejson" short:"f"`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

func (c *EncryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("encrypting secret", "file", c.File, "format", c.Format, "dry_run", c.DryRun)

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	filePath, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("error processing file or env %q: %v", c.File, err)
	}
	ctx.Logger.Debug("resolved file path", "path", filePath)

	// Check if file exists when not in dry run mode
	if !c.DryRun {
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				ctx.Logger.Debug("file does not exist", "path", filePath)
				return fmt.Errorf("file does not exist: %s", filePath)
			}
			ctx.Logger.Debug("error checking file", "path", filePath, "error", err)
			return fmt.Errorf("error checking file %s: %v", filePath, err)
		}
		ctx.Logger.Debug("file details", "path", filePath, "size", fileInfo.Size(), "mode", fileInfo.Mode())
	}

	ctx.Logger.Debug("encrypting file", "path", filePath)
	n, err := esec.EncryptFileInPlace(filePath)
	if err != nil {
		ctx.Logger.Debug("encryption failed", "path", filePath, "error", err)
		return fmt.Errorf("error encrypting file %s: %v", filePath, err)
	}

	ctx.Logger.Debug("encryption successful", "path", filePath, "bytes", n)
	fmt.Printf("Encrypted %d bytes\n", n)
	return nil
}

type DecryptCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("decrypting secret", "file", c.File, "format", c.Format, "key_dir", c.KeyDir, "key_from_stdin", c.KeyFromStdin)

	var key string
	if c.KeyFromStdin {
		ctx.Logger.Debug("reading private key from stdin")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			ctx.Logger.Debug("stdin read failed", "error", err)
			return fmt.Errorf("error reading from stdin: %v", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("private key read from stdin", "key_length", len(key))
	} else {
		ctx.Logger.Debug("using key from keyring", "key_dir", c.KeyDir)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("error processing file or env: %v", err)
	}
	ctx.Logger.Debug("resolved file path", "path", fileName)

	// Check if file exists
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", fileName)
			return fmt.Errorf("file does not exist: %s", fileName)
		}
		ctx.Logger.Debug("error checking file", "path", fileName, "error", err)
		return fmt.Errorf("error checking file %s: %v", fileName, err)
	}
	ctx.Logger.Debug("file details", "path", fileName, "size", fileInfo.Size(), "mode", fileInfo.Mode())

	ctx.Logger.Debug("decrypting file", "path", fileName)
	var buf bytes.Buffer
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		ctx.Logger.Debug("decryption failed", "path", fileName, "error", err)
		return fmt.Errorf("error decrypting file %s: %v", fileName, err)
	}

	ctx.Logger.Debug("decryption successful", "path", fileName, "bytes", len(data))
	buf.Read(data)
	fmt.Println(string(data))
	return nil
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

type GetCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Key          string `arg:"" help:"Key to extract from decrypted content" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *GetCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("getting key from secret", "file", c.File, "key", c.Key, "format", c.Format, "key_dir", c.KeyDir, "key_from_stdin", c.KeyFromStdin)

	var key string
	if c.KeyFromStdin {
		ctx.Logger.Debug("reading private key from stdin")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			ctx.Logger.Debug("stdin read failed", "error", err)
			return fmt.Errorf("error reading from stdin: %v", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("private key read from stdin", "key_length", len(key))
	} else {
		ctx.Logger.Debug("using key from keyring", "key_dir", c.KeyDir)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("error processing file or env: %v", err)
	}
	ctx.Logger.Debug("resolved file path", "path", fileName)

	format, _ = fileutils.ParseFormat(fileName)

	// Check if file exists
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", fileName)
			return fmt.Errorf("file does not exist: %s", fileName)
		}
		ctx.Logger.Debug("error checking file", "path", fileName, "error", err)
		return fmt.Errorf("error checking file %s: %v", fileName, err)
	}
	ctx.Logger.Debug("file details", "path", fileName, "size", fileInfo.Size(), "mode", fileInfo.Mode())

	ctx.Logger.Debug("decrypting file", "path", fileName)
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		ctx.Logger.Debug("decryption failed", "path", fileName, "error", err)
		return fmt.Errorf("error decrypting file %s: %v", fileName, err)
	}

	ctx.Logger.Debug("decryption successful", "path", fileName, "bytes", len(data))

	// Parse the data based on format and extract the key
	var value string

	switch format {
	case fileutils.Env:
		// Parse .env format
		envVars, err := esec.DotEnvToEnv(data)
		if err != nil {
			ctx.Logger.Debug("env parsing failed", "error", err)
			return fmt.Errorf("error parsing decrypted .env: %v", err)
		}
		val, exists := envVars[c.Key]
		if !exists {
			ctx.Logger.Debug("key not found", "key", c.Key)
			return fmt.Errorf("key %q not found in decrypted content", c.Key)
		}
		value = val

	case fileutils.Ejson:
		// Parse JSON format
		var jsonData map[string]interface{}
		if err := gojson.Unmarshal(data, &jsonData); err != nil {
			ctx.Logger.Debug("json parsing failed", "error", err)
			return fmt.Errorf("error parsing decrypted JSON: %v", err)
		}

		// Handle nested keys with dot notation
		keys := strings.Split(c.Key, ".")
		current := jsonData

		// Navigate through nested objects
		for i, k := range keys[:len(keys)-1] {
			nextObj, ok := current[k].(map[string]interface{})
			if !ok {
				ctx.Logger.Debug("invalid key path", "key", c.Key, "failed_at", strings.Join(keys[:i+1], "."))
				return fmt.Errorf("key path %q is invalid at %q", c.Key, strings.Join(keys[:i+1], "."))
			}
			current = nextObj
		}

		// Get the final value
		lastKey := keys[len(keys)-1]
		val, exists := current[lastKey]
		if !exists {
			ctx.Logger.Debug("key not found", "key", c.Key)
			return fmt.Errorf("key %q not found in decrypted content", c.Key)
		}

		// Convert the value to string based on type
		switch v := val.(type) {
		case string:
			value = v
		case float64, int, bool:
			value = fmt.Sprintf("%v", v)
		default:
			// For complex objects, return as JSON
			valueBytes, err := gojson.Marshal(v)
			if err != nil {
				ctx.Logger.Debug("json marshaling failed", "key", c.Key, "error", err)
				return fmt.Errorf("error serializing value for key %q: %v", c.Key, err)
			}
			value = string(valueBytes)
		}

	default:
		return fmt.Errorf("unsupported format for get command: %s", format)
	}

	// Output just the value without newline
	fmt.Print(value)
	return nil
}

// Add this command struct
type RunCmd struct {
	File         string   `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string   `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool     `help:"Read the key from stdin" short:"k"`
	KeyDir       string   `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
	Command      []string `arg:"" optional:"" name:"command" help:"Command to run with the decrypted environment variables"`
}

// Implement the Run method
func (c *RunCmd) Run(ctx *cliCtx) error {
	// Validate that a command is specified
	if len(c.Command) == 0 {
		return fmt.Errorf("no command specified to run")
	}

	// Use structured logging for debug information
	ctx.Logger.Debug("preparing to run command", "command", strings.Join(c.Command, " "))

	// Read the private key from stdin if requested
	var key string
	if c.KeyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("read private key from stdin")
	}

	// Parse the file format
	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	// Process the file or environment name to get the actual filename
	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		return fmt.Errorf("error processing file or env: %v", err)
	}

	ctx.Logger.Debug("using secrets file", "file", fileName)

	// Check if the file exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return fmt.Errorf("secrets file %s does not exist", fileName)
	}

	// Decrypt the file
	ctx.Logger.Debug("decrypting file", "file", fileName)

	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %v", err)
	}

	ctx.Logger.Debug("successfully decrypted secrets file")

	// Convert decrypted data to environment variables
	var envVars map[string]string
	switch format {
	case fileutils.Env:
		envVars, err = esec.DotEnvToEnv(data)
		if err != nil {
			return fmt.Errorf("error parsing decrypted .env: %v", err)
		}
	case fileutils.Ejson:
		envVars, err = esec.EjsonToEnv(data)
		if err != nil {
			return fmt.Errorf("error parsing decrypted EJSON: %v", err)
		}
	default:
		return fmt.Errorf("unsupported format for run command: %s", format)
	}

	// Validate we have environment variables
	if len(envVars) == 0 {
		ctx.Logger.Debug("warning: no environment variables found in the decrypted file")
	} else {
		ctx.Logger.Debug("loaded environment variables", "count", len(envVars))
	}

	ctx.Logger.Debug("executing command", "command", strings.Join(c.Command, " "))

	// Create a command to run
	cmd := exec.Command(c.Command[0], c.Command[1:]...)

	// Set up environment variables
	cmd.Env = os.Environ() // Start with current environment
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Connect stdin, stdout, stderr for full terminal support
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Ensure proper terminal handling
	if runtime.GOOS != "windows" {
		// For Unix-like systems, we'll use a new process group but keep terminal control
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			// Set the process as the controlling terminal process
			Ctty: int(os.Stdin.Fd()),
			// For interactive apps, ensure terminal control is transferred
			Foreground: true,
		}
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}

	// Process ID for signal handling
	pid := cmd.Process.Pid
	ctx.Logger.Debug("started process", "pid", pid)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Use a channel to coordinate between signal handler and main process
	done := make(chan error, 1)

	// Start a goroutine to wait for the command to finish
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for either the command to finish or a signal
	select {
	case sig := <-sigChan:
		// Immediately stop catching additional signals to prevent deadlock
		signal.Stop(sigChan)
		close(sigChan)

		ctx.Logger.Debug("received signal", "signal", sig.String())

		// We're running a terminal app, so just forward the signal and exit
		// This lets the terminal handle the subprocess properly
		if runtime.GOOS != "windows" {
			// Just forward the signal and exit immediately
			// This works better for terminal applications
			syscall.Kill(pid, sig.(syscall.Signal))
		} else {
			// Windows handling
			cmd.Process.Kill()
		}

		// Return to let the terminal clean up properly
		return nil

	case err := <-done:
		// Command completed on its own
		signal.Stop(sigChan)

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				ctx.Logger.Debug("command exited with error", "code", exitErr.ExitCode())
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("error running command: %v", err)
		}

		ctx.Logger.Debug("command completed successfully")
		return nil
	}
}
