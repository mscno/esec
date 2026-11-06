//go:build !windows

//nolint:gosec // subprocesses use synthetic blob fixtures and temporary paths
package commands

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBlobImportRejectsFIFOWithoutBlocking(t *testing.T) {
	root, ctx := blobFixture(t, "env")
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, ".env.dev"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- (&BlobSetCmd{Environment: "dev", Key: "BAD", From: path, Create: true}).Run(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO import blocked")
	}
	after, err := os.ReadFile(filepath.Join(root, ".env.dev"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected FIFO import changed ciphertext", err)
	}
}

func TestBlobSignalHelper(t *testing.T) {
	if os.Getenv("ESEC_TEST_BLOB_SIGNAL_HELPER") != "1" {
		return
	}
	script := `printf '%s' "$CRED_PATH" > "$READY"; exec sleep 30`
	if os.Getenv("ESEC_TEST_BLOB_IGNORE_SIGNAL") == "1" {
		script = `trap '' INT TERM; printf '%s' "$CRED_PATH" > "$READY"; exec sleep 30`
	}
	err := (&BlobRunCmd{Environment: "dev", Files: []string{"CRED_PATH=SELECTED"}, Command: []string{"sh", "-c", script}}).Run(&cliCtx{Logger: slog.New(slog.DiscardHandler), Quiet: true})
	var exit *ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.Code)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestBlobRunSignalsCleanPrivateFiles(t *testing.T) { //nolint:gocyclo // end-to-end signal, permissions, readiness and cleanup assertions
	for _, test := range []struct {
		name   string
		signal syscall.Signal
		ignore bool
	}{{"interrupt", syscall.SIGINT, false}, {"terminate", syscall.SIGTERM, false}, {"ignores-terminate", syscall.SIGTERM, true}} {
		t.Run(test.name, func(t *testing.T) {
			root, ctx := blobFixture(t, "env")
			setTestBlob(t, ctx, "SELECTED", []byte("signal-test-secret"), true)
			base := t.TempDir()
			t.Setenv("TMPDIR", base)
			ready := filepath.Join(t.TempDir(), "ready")
			t.Setenv("READY", ready)
			t.Setenv("ESEC_TEST_BLOB_SIGNAL_HELPER", "1")
			if test.ignore {
				t.Setenv("ESEC_TEST_BLOB_IGNORE_SIGNAL", "1")
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-test.run=^TestBlobSignalHelper$")
			cmd.Dir = root
			cmd.Env = os.Environ()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGTERM) })
			deadline := time.Now().Add(10 * time.Second)
			var path string
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(ready)
				if err == nil && len(data) > 0 {
					path = string(data)
					break
				}
				select {
				case err := <-done:
					t.Fatal("helper exited before readiness", err)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if path == "" {
				t.Fatal("child never ready")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("temporary file not 0600", err)
			}
			info, err = os.Stat(filepath.Dir(path))
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatal("temporary directory not 0700", err)
			}
			if err := cmd.Process.Signal(test.signal); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 128+int(test.signal) {
					t.Fatal("signal exit status not preserved", err)
				}
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("helper did not stop")
			}
			entries, err := os.ReadDir(base)
			if err != nil || len(entries) != 0 {
				t.Fatal("signal left plaintext behind", err)
			}
		})
	}
}
