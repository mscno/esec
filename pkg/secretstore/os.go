package secretstore

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// osStore uses the platform credential store through go-keyring.
type osStore struct{}

func (osStore) Backend() string     { return BackendOS }
func (osStore) HardwareBound() bool { return true }

func (osStore) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	v, err := keyring.Get(Service, name)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("os secret store get: %w", err)
	}
	return v, nil
}

func (osStore) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := keyring.Set(Service, name, value); err != nil {
		return fmt.Errorf("os secret store set: %w", err)
	}
	return nil
}

func (osStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := keyring.Delete(Service, name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("os secret store delete: %w", err)
	}
	return nil
}

// osAvailable reports whether the OS store answers. macOS and Windows always
// have one; on Linux the Secret Service may be missing, which is the normal
// state of a headless VM. The probe is bounded because a D-Bus autolaunch can
// stall.
func osAvailable() bool {
	if runtime.GOOS != "linux" {
		return true
	}
	done := make(chan error, 1)
	go func() {
		_, err := keyring.Get(Service, "availability-probe")
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil || errors.Is(err, keyring.ErrNotFound)
	case <-time.After(3 * time.Second):
		return false
	}
}
