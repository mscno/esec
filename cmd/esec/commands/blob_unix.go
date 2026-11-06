//go:build !windows

package commands

import (
	"os"
	"os/exec"
	"syscall"
)

func blobDiskSupported() error { return nil }

// Nonblocking open prevents a substituted FIFO from hanging before file.Stat.
func openBlobInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // user-selected input is validated on the opened descriptor before reading
}

func setBlobProcAttr(cmd *exec.Cmd) {
	setProcAttr(cmd)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
}

func signalBlobChild(cmd *exec.Cmd, sig os.Signal, kill bool) {
	s, ok := sig.(syscall.Signal)
	if kill {
		s, ok = syscall.SIGKILL, true
	}
	if ok {
		_ = syscall.Kill(-cmd.Process.Pid, s)
	}
}

func blobSignalExit(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 1
}
