// Package filelock provides nonblocking process locks released by the kernel
// when a writer exits or crashes. The lock file is intentionally persistent.
package filelock

import (
	"fmt"
	"os"
	"path/filepath"
)

// Acquire locks a directory's writer lock until release. Never unlink the lock
// file while writers may be running: doing so permits locks on different inodes.
func Acquire(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil { //nolint:gosec // caller-selected keyring/store directory
		return nil, err
	}
	p := filepath.Join(dir, ".mutation-lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600) //nolint:gosec // caller-selected store directory
	if err != nil {
		return nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("writer busy at %s: %w", p, err)
	}
	return func() { _ = unlock(f); _ = f.Close() }, nil
}
