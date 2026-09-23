//go:build windows

package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// execExternal runs the given binary as a child process, forwarding
// arguments, environment, and stdio, and returns its exit code. Windows has no
// execve equivalent, so the child exit code is propagated instead.
func execExternal(bin string, args []string) int {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "esec: failed to run %s: %v\n", bin, err)
		return 1
	}
	return 0
}
