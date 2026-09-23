//go:build !windows

package commands

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/term"
)

// setProcAttr configures terminal handling for the child process when attached
// to a real terminal. In non-TTY contexts (CI pipelines, redirected stdio) we
// must not request a controlling terminal, or the child fails with ENOTTY.
func setProcAttr(cmd *exec.Cmd) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	// Use a new process group but keep terminal control
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		// Set the process as the controlling terminal process
		Ctty: int(os.Stdin.Fd()),
		// For interactive apps, ensure terminal control is transferred
		Foreground: true,
	}
}

// forwardSignal forwards a signal to the child process and returns the exit
// code esec should use: 128+signal per Unix convention (e.g. 130 for SIGINT).
func forwardSignal(cmd *exec.Cmd, sig os.Signal) int {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return 1
	}
	_ = syscall.Kill(cmd.Process.Pid, s)
	return 128 + int(s)
}
