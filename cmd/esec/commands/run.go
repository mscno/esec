package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

// RunCmd decrypts a secrets file and runs a command with the environment variables.
type RunCmd struct {
	File         string   `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string   `help:"File format (ejson, env, eyaml, etoml)" default:"" short:"f" env:"ESEC_FORMAT"`
	KeyFromStdin bool     `help:"Read the key from stdin" short:"k"`
	KeyDir       string   `help:"Directory containing the '.esec-keyring' file" default:"." short:"d" env:"ESEC_KEY_DIR"`
	Command      []string `arg:"" optional:"" name:"command" help:"Command to run with the decrypted environment variables"`
}

// Run executes the run command, decrypting secrets and running the specified command.
func (c *RunCmd) Run(ctx *cliCtx) error {
	// Validate that a command is specified
	if len(c.Command) == 0 {
		return fmt.Errorf("no command to run: esec run <file or env> -- <command> [args...], for example: esec run prod -- ./server")
	}

	// Validate the command is safe to execute
	if err := validateCommand(c.Command); err != nil {
		return err
	}

	// Use structured logging for debug information
	ctx.Logger.Debug("preparing to run command", "command", strings.Join(c.Command, " "))

	envVars, fileName, err := decryptEnvVars(ctx, c.File, c.Format, c.KeyDir, c.KeyFromStdin)
	if err != nil {
		return viaVault(err, c.File, func(env string) []string {
			return append(append(withFormat([]string{"run", env}, c.Format), "--"), c.Command...)
		})
	}

	// Validate we have environment variables
	if len(envVars) == 0 {
		ctx.Logger.Warn("no environment variables found in decrypted file", "file", fileName)
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

	// Platform-specific terminal handling (no-op on Windows and in non-TTY contexts)
	setProcAttr(cmd)

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
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

		// Forward the signal to the child and exit with the conventional
		// code for the signal (e.g. 130 for SIGINT on Unix).
		return &ExitError{Code: forwardSignal(cmd, sig)}

	case err := <-done:
		// Command completed on its own
		signal.Stop(sigChan)

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				ctx.Logger.Debug("command exited with error", "code", exitErr.ExitCode())
				// Propagate the child exit code, like `make` and `env` do
				return &ExitError{Code: exitErr.ExitCode()}
			}
			return fmt.Errorf("running command: %w", err)
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
		// Unix shell metacharacters
		if strings.Contains(arg, "$(") || strings.Contains(arg, "`") {
			return fmt.Errorf("command contains potentially unsafe shell metacharacters")
		}

		// Windows-specific metacharacters
		if runtime.GOOS == "windows" {
			// Check for Windows variable expansion
			if strings.Contains(arg, "%") {
				return fmt.Errorf("command contains potentially unsafe Windows metacharacters")
			}
			// Check for Windows shell operators
			for _, char := range []string{"&", "|", "^", "<", ">"} {
				if strings.Contains(arg, char) {
					return fmt.Errorf("command contains potentially unsafe Windows metacharacter: %s", char)
				}
			}
		}
	}

	return nil
}
