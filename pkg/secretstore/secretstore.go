// Package secretstore keeps small device secrets (keys, tokens) out of plain
// files where the platform allows it. esec and esec-vault share one store so a
// secret written by one tool is found by the other.
//
// The backend is chosen once and recorded in <home>/secret-store.toml:
//
//	backend = "os"        # macOS Keychain, Windows Credential Manager, Linux Secret Service
//	backend = "tpm"       # Linux: systemd-creds sealed to the TPM; survives reboots
//	backend = "file"      # 0600 file; survives reboots, no hardware binding
//	backend = "keyctl"    # Linux kernel user keyring; cleared at reboot
//
// ESEC_SECRET_STORE overrides the recorded choice. Without either, the OS
// store is used. Detect picks the best backend for the current machine; only
// esec-vault calls it, when it first needs to store a device secret.
package secretstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/pelletier/go-toml/v2"
)

// Service is the name every backend files secrets under.
const Service = "esec-vault"

// Backend names.
const (
	BackendOS     = "os"
	BackendTPM    = "tpm"
	BackendFile   = "file"
	BackendKeyctl = "keyctl"
)

// EnvBackend overrides the configured backend.
const EnvBackend = "ESEC_SECRET_STORE"

// ErrNotFound is returned by Get when the secret does not exist.
var ErrNotFound = errors.New("secret not found in secret store")

// ErrUnavailable is returned when a backend cannot be used on this machine.
var ErrUnavailable = errors.New("secret store backend unavailable")

// Store stores and retrieves named secrets.
type Store interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
	// Backend reports the backend name, for status output.
	Backend() string
	// HardwareBound reports whether stored secrets are protected by something
	// other than file permissions (an OS keychain or a TPM).
	HardwareBound() bool
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidName reports whether name is an acceptable secret name. Names become
// file names and keyring descriptions, so they are restricted.
func ValidName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	return nil
}

// Home returns the esec-vault home directory: $ESEC_VAULT_HOME, else
// $XDG_CONFIG_HOME/esec, else ~/.config/esec.
func Home() string {
	if h := os.Getenv("ESEC_VAULT_HOME"); h != "" {
		return h
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "esec")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "esec")
	}
	return ".esec-vault"
}

// Config is the content of secret-store.toml.
type Config struct {
	// Backend is the selected backend name.
	Backend string `toml:"backend"`
	// SealKeyrings makes newly created keyring files sealed under the cache key.
	SealKeyrings bool `toml:"seal_keyrings"`
}

// ConfigPath returns the location of secret-store.toml.
func ConfigPath() string { return filepath.Join(Home(), "secret-store.toml") }

// LoadConfig reads secret-store.toml; a missing file yields the zero Config.
func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", ConfigPath(), err)
	}
	if c.Backend != "" && !knownBackend(c.Backend) {
		return nil, fmt.Errorf("invalid %s: unknown backend %q", ConfigPath(), c.Backend)
	}
	return &c, nil
}

// SaveConfig writes secret-store.toml atomically with private permissions.
func SaveConfig(c *Config) error {
	if c.Backend != "" && !knownBackend(c.Backend) {
		return fmt.Errorf("unknown backend %q", c.Backend)
	}
	data, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	return writePrivate(ConfigPath(), data)
}

func knownBackend(b string) bool {
	switch b {
	case BackendOS, BackendTPM, BackendFile, BackendKeyctl:
		return true
	}
	return false
}

// Selected returns the backend in effect: ESEC_SECRET_STORE, then the
// configured backend, then the OS store.
func Selected() (string, error) {
	if b := os.Getenv(EnvBackend); b != "" {
		if !knownBackend(b) {
			return "", fmt.Errorf("%s: unknown backend %q", EnvBackend, b)
		}
		return b, nil
	}
	c, err := LoadConfig()
	if err != nil {
		return "", err
	}
	if c.Backend != "" {
		return c.Backend, nil
	}
	return BackendOS, nil
}

// Configured reports whether a backend has been chosen explicitly, either by
// environment or in secret-store.toml.
func Configured() bool {
	if os.Getenv(EnvBackend) != "" {
		return true
	}
	c, err := LoadConfig()
	return err == nil && c.Backend != ""
}

// Default opens the selected backend.
func Default() (Store, error) {
	b, err := Selected()
	if err != nil {
		return nil, err
	}
	return Open(b)
}

// Open returns the named backend.
func Open(backend string) (Store, error) {
	switch backend {
	case BackendOS:
		return osStore{}, nil
	case BackendFile:
		return NewFile(filepath.Join(Home(), "secrets", "device.toml")), nil
	case BackendTPM:
		return newTPM(filepath.Join(Home(), "secrets"), systemdCreds)
	case BackendKeyctl:
		return newKeyctl()
	}
	return nil, fmt.Errorf("unknown secret store backend %q", backend)
}

// Detect chooses the best available backend for this machine without storing
// the choice. The OS store wins wherever it answers; on Linux without a
// Secret Service, a working TPM is preferred, then the 0600 file.
func Detect() string {
	if osAvailable() {
		return BackendOS
	}
	if s, err := Open(BackendTPM); err == nil {
		if probe(s) == nil {
			return BackendTPM
		}
	}
	return BackendFile
}

// EnsureSelected records a backend if none is configured yet and returns the
// store. Existing choices are never changed.
func EnsureSelected() (Store, error) {
	if Configured() {
		return Default()
	}
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	c.Backend = Detect()
	if err := SaveConfig(c); err != nil {
		return nil, err
	}
	return Open(c.Backend)
}

// probe writes, reads back and deletes a throwaway secret.
func probe(s Store) error {
	const name = "probe"
	if err := s.Set(name, "ok"); err != nil {
		return err
	}
	got, err := s.Get(name)
	_ = s.Delete(name)
	if err != nil {
		return err
	}
	if got != "ok" {
		return fmt.Errorf("%w: probe read back different data", ErrUnavailable)
	}
	return nil
}

// writePrivate writes data atomically to path with 0600 permissions inside a
// 0700 directory.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".secret-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
