package commands

import (
	"fmt"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

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

	// Validate the command is safe to execute
	if err := validateCommand(c.Command); err != nil {
		return err
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
		// Sanitize variables to prevent injection
		envVars, err = esec.DotEnvToEnv(data)
		envVars = sanitizeEnvVars(envVars)
		if err != nil {
			return fmt.Errorf("error parsing decrypted .env: %v", err)
		}
	case fileutils.Ejson:
		envVars, err = esec.EjsonToEnv(data)
		envVars = sanitizeEnvVars(envVars)
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

// validateCommand checks if the command is safe to execute
func validateCommand(command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("no command specified to run")
	}

	// Validate that the command doesn't contain suspicious characters
	for _, arg := range command {
		if strings.Contains(arg, "$(") || strings.Contains(arg, "`") {
			return fmt.Errorf("command contains potentially unsafe shell metacharacters")
		}
	}

	return nil
}

// sanitizeEnvVars removes potentially dangerous environment variables
func sanitizeEnvVars(vars map[string]string) map[string]string {
	for k := range vars {
		if strings.Contains(k, "=") || strings.Contains(k, ";") || strings.Contains(k, "\n") {
			delete(vars, k)
		}
	}
	return vars
}
