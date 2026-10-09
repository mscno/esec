package filelock

import (
	"os"
	"os/exec"
	"testing"
)

func TestLockReleasedAfterProcessExit(t *testing.T) {
	if dir := os.Getenv("ESEC_TEST_LOCK_CHILD"); dir != "" {
		if _, err := Acquire(dir); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	unlock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := Acquire(dir); err == nil {
		release()
		t.Fatal("second writer accepted")
	}
	unlock()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLockReleasedAfterProcessExit$")
	cmd.Env = append(os.Environ(), "ESEC_TEST_LOCK_CHILD="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	// Child deliberately exited without release; the kernel must have unlocked.
	unlock, err = Acquire(dir)
	if err != nil {
		t.Fatal("stale lock after crash:", err)
	}
	unlock()
}
