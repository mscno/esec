package secretstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func exercise(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if err := s.Set("device-key", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("device-key", "v2"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("device-key"); err != nil || got != "v2" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := s.Delete("device-key"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("device-key"); err != nil {
		t.Fatal("deleting a missing secret must succeed")
	}
	if _, err := s.Get("device-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted secret still present: %v", err)
	}
	for _, bad := range []string{"", "../x", "A", "a/b", strings.Repeat("a", 65)} {
		if err := s.Set(bad, "v"); err == nil {
			t.Fatalf("invalid name %q accepted", bad)
		}
	}
}

func TestFileStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets", "device.toml")
	s := NewFile(p)
	exercise(t, s)
	if err := s.Set("a", "1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("file mode %04o", info.Mode().Perm())
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0644); err != nil { //nolint:gosec // deliberately loose to prove it is rejected
			t.Fatal(err)
		}
		if _, err := s.Get("a"); err == nil {
			t.Fatal("world-readable store accepted")
		}
		if err := os.Chmod(p, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "link.toml")
		if err := os.Symlink(p, link); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFile(link).Get("a"); err == nil {
			t.Fatal("symlinked store accepted")
		}
	}
}

func TestMemoryStore(t *testing.T) { exercise(t, NewMemory()) }

// TestTPMStoreProtocol drives the TPM backend against a stand-in for
// systemd-creds that checks the arguments and stores data verbatim, so the
// argument contract is covered on machines without a TPM.
func TestTPMStoreProtocol(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-creds")
	script := `#!/bin/sh
set -e
op="$1"; shift
case "$op" in
encrypt)
  [ "$1" = "--with-key=tpm2" ] || exit 9
  name="$2"; in="$3"; out="$4"
  [ "$in" = "-" ] || exit 9
  { echo "$name"; cat; } > "$out" ;;
decrypt)
  name="$1"; in="$2"
  [ "$(head -n 1 "$in")" = "$name" ] || { echo "credential name mismatch" >&2; exit 1; }
  tail -n +2 "$in" | tr -d '\n' ;;
*) exit 9 ;;
esac
`
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil { //nolint:gosec // executable test stand-in
		t.Fatal(err)
	}
	s, err := newTPM(filepath.Join(dir, "secrets"), fake)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
	if err := s.Set("one", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("two", "2"); err != nil {
		t.Fatal(err)
	}
	// Swapping credential files must fail: the name is bound into each one.
	secrets := filepath.Join(dir, "secrets")
	if err := os.Rename(filepath.Join(secrets, "two.cred"), filepath.Join(secrets, "one.cred")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("one"); err == nil {
		t.Fatal("swapped credential accepted")
	}
}

func TestSelectionAndConfig(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv(EnvBackend, "")
	if b, err := Selected(); err != nil || b != BackendOS {
		t.Fatalf("default backend = %q, %v", b, err)
	}
	if Configured() {
		t.Fatal("nothing configured yet")
	}
	if err := SaveConfig(&Config{Backend: BackendFile, SealKeyrings: true}); err != nil {
		t.Fatal(err)
	}
	if b, err := Selected(); err != nil || b != BackendFile {
		t.Fatalf("configured backend = %q, %v", b, err)
	}
	t.Setenv(EnvBackend, BackendOS)
	if b, _ := Selected(); b != BackendOS {
		t.Fatal("environment must override config")
	}
	t.Setenv(EnvBackend, "bogus")
	if _, err := Selected(); err == nil {
		t.Fatal("unknown backend accepted")
	}
	t.Setenv(EnvBackend, "")
	if err := os.WriteFile(ConfigPath(), []byte("backend = \"nope\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("unknown configured backend accepted")
	}
	if err := SaveConfig(&Config{Backend: BackendFile}); err != nil {
		t.Fatal(err)
	}
	s, err := EnsureSelected()
	if err != nil || s.Backend() != BackendFile {
		t.Fatal("EnsureSelected must keep an existing choice")
	}
}
