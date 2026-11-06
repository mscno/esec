package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mscno/esec/pkg/projectfile"
)

// BlobRunCmd passes only selected file paths, never blob values, to a child.
type BlobRunCmd struct {
	Environment string   `arg:"" help:"Exact environment or secrets file"`
	Files       []string `name:"file" required:"" help:"Expose a blob as VARIABLE=KEY (repeat for multiple files)" sep:"none"`
	Command     []string `arg:"" optional:"" name:"command" help:"Command to run; read file paths from the selected variables"`
}

type blobBinding struct {
	Variable string
	Key      string
}

// Run materializes files only after every selected blob has been decoded.
// Cleanup happens on command success, failure, start errors, SIGINT and SIGTERM.
func (c *BlobRunCmd) Run(ctx *cliCtx) (result error) {
	if err := blobDiskSupported(); err != nil {
		return err
	}
	if err := validateCommand(c.Command); err != nil {
		return err
	}
	bindings, err := c.bindings()
	if err != nil {
		return err
	}
	values, err := readBlobValues(c.Environment)
	if err != nil {
		return err
	}
	data := make([][]byte, 0, len(bindings))
	defer func() {
		for _, b := range data {
			clear(b)
		}
	}()
	for _, binding := range bindings {
		b, err := decodeBlobValue(values, binding.Key)
		if err != nil {
			return err
		}
		data = append(data, b)
	}

	// Catch signals before creating any plaintext file. The child inherits a new
	// process group so a forwarded signal reaches its ordinary descendants too.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	dir, err := os.MkdirTemp("", "esec-blob-*")
	if err != nil {
		return errors.New("could not create a private blob directory")
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			result = fmt.Errorf("could not remove temporary blob files: %w", err)
		}
	}()
	// TMPDIR can be relative; paths passed to the child must be absolute.
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	env := os.Environ()
	for i, binding := range bindings {
		path := filepath.Join(abs, "blob-"+strconv.Itoa(i))
		if err := writeBlobFile(path, data[i]); err != nil {
			return err
		}
		prefix := binding.Variable + "="
		env = slices.DeleteFunc(env, func(v string) bool { return strings.HasPrefix(v, prefix) })
		env = append(env, prefix+path)
	}
	return runBlobChild(ctx, c.Command, env, signals)
}

func (c *BlobRunCmd) bindings() ([]blobBinding, error) {
	if len(c.Files) == 0 {
		return nil, errors.New("blob run requires at least one --file VARIABLE=KEY")
	}
	bindings := make([]blobBinding, 0, len(c.Files))
	seen := map[string]bool{}
	for _, file := range c.Files {
		variable, key, ok := strings.Cut(file, "=")
		if !ok || key == "" {
			return nil, errors.New("expected --file VARIABLE=KEY")
		}
		if err := projectfile.ValidateRunVariable(variable); err != nil {
			return nil, err
		}
		if seen[variable] {
			return nil, errors.New("each blob file variable must be unique")
		}
		seen[variable] = true
		bindings = append(bindings, blobBinding{Variable: variable, Key: key})
	}
	return bindings, nil
}

func runBlobChild(ctx *cliCtx, command, env []string, signals <-chan os.Signal) error {
	// A signal received while preparing files must not start a child.
	select {
	case sig := <-signals:
		return &ExitError{Code: blobSignalExit(sig)}
	default:
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	setBlobProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}
	type childResult struct{ err error }
	done := make(chan childResult, 1)
	go func() { done <- childResult{err: cmd.Wait()} }()
	select {
	case result := <-done:
		err := result.err
		if err == nil {
			return nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ExitError{Code: exit.ExitCode()}
		}
		return fmt.Errorf("running command: %w", err)
	case sig := <-signals:
		ctx.Logger.Debug("forwarding signal before blob cleanup", "signal", sig.String())
		signalBlobChild(cmd, sig, false)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-signals:
			signalBlobChild(cmd, sig, true)
			<-done
		case <-timer.C:
			signalBlobChild(cmd, sig, true)
			<-done
		}
		// Ensure descendants that ignored the first signal cannot retain the
		// temporary files after the direct child exits.
		signalBlobChild(cmd, sig, true)
		return &ExitError{Code: blobSignalExit(sig)}
	}
}
