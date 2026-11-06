//go:build windows

package commands

import (
	"errors"
	"os"
	"os/exec"
)

func blobDiskSupported() error {
	return errors.New("private blob files require Unix permissions; on Windows use blob get to stdout")
}

func openBlobInput(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("blob input must be a regular file")
	}
	return os.Open(path)
}

func setBlobProcAttr(_ *exec.Cmd)                        {}
func signalBlobChild(cmd *exec.Cmd, _ os.Signal, _ bool) { _ = cmd.Process.Kill() }
func blobSignalExit(_ os.Signal) int                     { return 1 }
