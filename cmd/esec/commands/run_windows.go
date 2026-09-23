//go:build windows

package commands

import (
	"os"
	"os/exec"
)

// setProcAttr is a no-op on Windows; there are no Unix-style process groups
// or controlling terminals to configure.
func setProcAttr(cmd *exec.Cmd) {}

// forwardSignal terminates the child process and returns the exit code esec
// should use. Windows has no Unix-style signal forwarding.
func forwardSignal(cmd *exec.Cmd, sig os.Signal) int {
	_ = cmd.Process.Kill()
	return 1
}
