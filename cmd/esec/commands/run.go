package commands

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"golang.org/x/term"
)

// RunCmd decrypts a secrets file and runs a command with the environment variables.
type RunCmd struct {
	File         string   `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string   `help:"File format (ejson, env, eyaml, etoml)" default:".ejson" short:"f" env:"ESEC_FORMAT"`
	KeyFromStdin bool     `help:"Read the key from stdin" short:"k"`
	KeyDir       string   `help:"Directory containing the '.esec-keyring' file" default:"." short:"d" env:"ESEC_KEY_DIR"`
	Command      []string `arg:"" optional:"" name:"command" help:"Command to run with the decrypted environment variables"`
}

// Run executes the run command, decrypting secrets and running the specified command.
//
//nolint:gocyclo // Complex but necessary for signal handling and process management
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
			return fmt.Errorf("reading key from stdin: %w", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("read private key from stdin")
	}

	// Parse the file format (used only to resolve an environment name to a file)
	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("invalid format %q: %w", c.Format, err)
	}

	// Process the file or environment name to get the actual filename
	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		return fmt.Errorf("invalid file or environment %q: %w", c.File, err)
	}

	ctx.Logger.Debug("using secrets file", "file", fileName)

	// Check if the file exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return fmt.Errorf("secrets file %s does not exist", fileName)
	}

	// The actual format is determined by the file on disk
	fileFormat, err := fileutils.ParseFormat(fileName)
	if err != nil {
		return fmt.Errorf("determining format of %s: %w", fileName, err)
	}

	// Decrypt the file
	ctx.Logger.Debug("decrypting file", "file", fileName)

	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		return fmt.Errorf("decrypting file %s: %w", fileName, err)
	}

	ctx.Logger.Debug("successfully decrypted secrets file")

	// Convert decrypted data to environment variables
	var envVars map[string]string
	switch fileFormat {
	case fileutils.Env:
		envVars, err = esec.DotEnvToEnv(data)
		if err != nil {
			return fmt.Errorf("parsing decrypted .env: %w", err)
		}
		// Sanitize variables to prevent injection (after error check)
		envVars = sanitizeEnvVars(envVars)
	case fileutils.Ejson:
		envVars, err = esec.EjsonToEnv(data)
		if err != nil {
			return fmt.Errorf("parsing decrypted EJSON: %w", err)
		}
		// Sanitize variables to prevent injection (after error check)
		envVars = sanitizeEnvVars(envVars)
	default:
		return fmt.Errorf("unsupported format for run command: %s", fileFormat)
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

	// Ensure proper terminal handling when attached to a real terminal.
	// In non-TTY contexts (CI pipelines, redirected stdio) we must not
	// request a controlling terminal, or the child fails with ENOTTY.
	if runtime.GOOS != "windows" && stdinIsTerminal() {
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

		// We're running a terminal app, so just forward the signal and exit.
		// This lets the terminal handle the subprocess properly.
		if runtime.GOOS != "windows" {
			s, ok := sig.(syscall.Signal)
			if !ok {
				return &ExitError{Code: 1}
			}
			_ = syscall.Kill(pid, s)
			// Exit with 128+signal per Unix convention (e.g. 130 for SIGINT)
			return &ExitError{Code: 128 + int(s)}
		}
		// Windows handling
		_ = cmd.Process.Kill()
		return &ExitError{Code: 1}

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

// stdinIsTerminal reports whether stdin is attached to a terminal.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
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

// sanitizeEnvVars removes potentially dangerous environment variables
func sanitizeEnvVars(vars map[string]string) map[string]string {
	for k := range vars {
		if strings.Contains(k, "=") || strings.Contains(k, ";") || strings.Contains(k, "\n") {
			delete(vars, k)
		}
	}
	return vars
}
