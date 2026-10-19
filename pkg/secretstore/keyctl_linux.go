//go:build linux

package secretstore

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// keyctlStore keeps secrets in the kernel user keyring. Secrets survive
// logouts but not reboots, which suits throwaway machines.
type keyctlStore struct{}

func newKeyctl() (Store, error) { return keyctlStore{}, nil }

func (keyctlStore) Backend() string     { return BackendKeyctl }
func (keyctlStore) HardwareBound() bool { return false }

func desc(name string) string { return Service + ":" + name }

func (k keyctlStore) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	id, err := k.find(name)
	if err != nil {
		return "", err
	}
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil {
		return "", fmt.Errorf("keyctl read: %w", err)
	}
	buf := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return "", fmt.Errorf("keyctl read: %w", err)
	}
	return string(buf[:n]), nil
}

func (keyctlStore) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	id, err := unix.AddKey("user", desc(name), []byte(value), unix.KEY_SPEC_USER_KEYRING)
	if err != nil {
		return fmt.Errorf("keyctl add: %w", err)
	}
	// Possessor and owning user only: view, read, write, search, link, setattr.
	const perm = 0x3f3f0000
	if err := unix.KeyctlSetperm(id, perm); err != nil {
		return fmt.Errorf("keyctl setperm: %w", err)
	}
	return nil
}

func (k keyctlStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	id, err := k.find(name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id, unix.KEY_SPEC_USER_KEYRING, 0, 0); err != nil {
		return fmt.Errorf("keyctl unlink: %w", err)
	}
	return nil
}

func (keyctlStore) find(name string) (int, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", desc(name), 0)
	if err != nil {
		if errors.Is(err, unix.ENOKEY) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("keyctl search: %w", err)
	}
	return id, nil
}
