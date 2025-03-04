package commands

import (
	"bytes"
	"context"
	gojson "encoding/json"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
)

type cliCtx struct {
	Debug bool
	context.Context
}

type cli struct {
	Keygen  KeygenCmd        `cmd:"" help:"Generate key"`
	Encrypt EncryptCmd       `cmd:"" help:"Encrypt a secret"`
	Decrypt DecryptCmd       `cmd:"" help:"Decrypt a secret"`
	Run     RunCmd           `cmd:"" help:"Decrypt a secret, set environment variables, and run a command"`
	Version kong.VersionFlag `help:"Show version"`
	Debug   bool             `help:"Enable debug mode"`
}

func Execute(version string) {
	var cli cli
	ctx := kong.Parse(&cli,
		kong.UsageOnError(),
		kong.Name("esec"),
		kong.Description("esec is a tool for encrypting secrets"),
		kong.Vars{"version": version},
	)

	err := ctx.Run(&cliCtx{Context: context.Background(), Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

type KeygenCmd struct {
}

func (c *KeygenCmd) Run(ctx *cliCtx) error {
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}

	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}

type EncryptCmd struct {
	File   string `arg:"" help:"File or Environment to encrypt" default:""`
	Format string `help:"File format" default:".ejson" short:"f"`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

func (c *EncryptCmd) Run(ctx *cliCtx) error {
	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	filePath, err := processFileOrEnv(c.File, format)
	if err != nil {
		return fmt.Errorf("error processing file or env %q: %v", c.File, err)
	}

	n, err := esec.EncryptFileInPlace(filePath)
	fmt.Printf("Encrypted %d bytes\n", n)
	return err
}

type DecryptCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *cliCtx) error {
	var key string
	if c.KeyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key = string(data)
		key = strings.TrimSpace(key)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		fmt.Errorf("error processing file or env: %v", err)
	}

	var buf bytes.Buffer
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		return err
	}

	buf.Read(data)
	fmt.Println(string(data))
	return nil
}

func processFileOrEnv(input string, defaultFileFormat fileutils.FileFormat) (filename string, err error) {
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

// Add this command struct
type RunCmd struct {
	File         string   `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string   `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool     `help:"Read the key from stdin" short:"k"`
	KeyDir       string   `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
	Command      []string `arg:"" optional:"" name:"command" help:"Command to run with the decrypted environment variables"`
}

// Implement the Run method
// Implement the Run method
func (c *RunCmd) Run(ctx *cliCtx) error {
	// Validate that a command is specified
	if len(c.Command) == 0 {
		return fmt.Errorf("no command specified to run")
	}

	fmt.Printf("Preparing to run command: %s\n", strings.Join(c.Command, " "))

	// Read the private key from stdin if requested
	var key string
	if c.KeyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(data))
		fmt.Println("Read private key from stdin")
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
	fmt.Printf("Using secrets file: %s\n", fileName)

	// Check if the file exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return fmt.Errorf("secrets file %s does not exist", fileName)
	}

	// Decrypt the file
	fmt.Printf("Decrypting %s...\n", fileName)
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %v", err)
	}
	fmt.Println("Successfully decrypted secrets file")

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
			// For EJSON files that don't have an "environment" section, try to parse as raw key-value
			// This is a fallback for EJSON files that don't follow the expected format
			var rawData map[string]interface{}
			if err := gojson.Unmarshal(data, &rawData); err == nil {
				envVars = make(map[string]string)
				for k, v := range rawData {
					// Skip the public key and metadata
					if k == "_ESEC_PUBLIC_KEY" || strings.HasPrefix(k, "_") {
						continue
					}
					// Only add string values
					if strVal, ok := v.(string); ok {
						envVars[k] = strVal
					}
				}
			} else {
				return fmt.Errorf("error parsing decrypted EJSON: %v", err)
			}
		}
	default:
		return fmt.Errorf("unsupported format for run command: %s", format)
	}

	// Validate we have environment variables
	if len(envVars) == 0 {
		fmt.Println("Warning: No environment variables found in the decrypted file")
	} else {
		fmt.Printf("Loaded %d environment variables\n", len(envVars))
	}

	// Create a command to run
	fmt.Printf("Executing: %s\n", strings.Join(c.Command, " "))
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
	fmt.Printf("Started process with PID: %d\n", pid)

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
				fmt.Printf("Command exited with code: %d\n", exitErr.ExitCode())
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("error running command: %v", err)
		}

		fmt.Println("Command completed successfully")
		return nil
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			// Pass the exit code back to the parent
			fmt.Printf("Command exited with code: %d\n", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("error running command: %v", err)
	}

	fmt.Println("Command completed successfully")
	return nil
}
