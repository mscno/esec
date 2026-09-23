package esec

import (
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/projectfile"
)

const testPrivateKeyHex = "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5"

func writeKeyring(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalKeyringStore(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	want, _ := hex.DecodeString(testPrivateKeyHex)

	t.Run("project keyring from global store", func(t *testing.T) {
		globalDir := t.TempDir()
		t.Setenv(EsecKeyringDir, globalDir)

		repo := t.TempDir()
		if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
			t.Fatal(err)
		}
		writeKeyring(t, filepath.Join(globalDir, "org_repo.keyring"),
			"ESEC_PRIVATE_KEY_DEV="+testPrivateKeyHex+"\n")

		key, err := findPrivateKey(repo, "dev", "", logger)
		if err != nil {
			t.Fatalf("findPrivateKey: %v", err)
		}
		if key != [32]byte(want) {
			t.Fatalf("unexpected key: %x", key)
		}
	})

	t.Run("default keyring fallback", func(t *testing.T) {
		globalDir := t.TempDir()
		t.Setenv(EsecKeyringDir, globalDir)

		repo := t.TempDir() // no .esec-project
		writeKeyring(t, filepath.Join(globalDir, DefaultKeyringBasename),
			"ESEC_PRIVATE_KEY="+testPrivateKeyHex+"\n")

		key, err := findPrivateKey(repo, "", "", logger)
		if err != nil {
			t.Fatalf("findPrivateKey: %v", err)
		}
		if key != [32]byte(want) {
			t.Fatalf("unexpected key: %x", key)
		}
	})

	t.Run("repo-local beats global", func(t *testing.T) {
		globalDir := t.TempDir()
		t.Setenv(EsecKeyringDir, globalDir)

		repo := t.TempDir()
		if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
			t.Fatal(err)
		}
		localKey := "1111111111111111111111111111111111111111111111111111111111111111"
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			"ESEC_PRIVATE_KEY_DEV="+localKey+"\n")
		writeKeyring(t, filepath.Join(globalDir, "org_repo.keyring"),
			"ESEC_PRIVATE_KEY_DEV="+testPrivateKeyHex+"\n")

		key, err := findPrivateKey(repo, "dev", "", logger)
		if err != nil {
			t.Fatalf("findPrivateKey: %v", err)
		}
		wantLocal, _ := hex.DecodeString(localKey)
		if key != [32]byte(wantLocal) {
			t.Fatalf("repo-local keyring should win, got: %x", key)
		}
	})

	t.Run("existing project keyring without key is terminal", func(t *testing.T) {
		globalDir := t.TempDir()
		t.Setenv(EsecKeyringDir, globalDir)

		repo := t.TempDir()
		if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
			t.Fatal(err)
		}
		writeKeyring(t, filepath.Join(globalDir, "org_repo.keyring"),
			"ESEC_PRIVATE_KEY_PROD="+testPrivateKeyHex+"\n")
		// A default keyring holding the wanted key must NOT be consulted.
		writeKeyring(t, filepath.Join(globalDir, DefaultKeyringBasename),
			"ESEC_PRIVATE_KEY_DEV="+testPrivateKeyHex+"\n")

		_, err := findPrivateKey(repo, "dev", "", logger)
		if err == nil {
			t.Fatal("expected error for missing key in existing keyring")
		}
	})

	t.Run("no keyring anywhere", func(t *testing.T) {
		globalDir := t.TempDir()
		t.Setenv(EsecKeyringDir, globalDir)
		repo := t.TempDir()

		_, err := findPrivateKey(repo, "dev", "", logger)
		if err == nil {
			t.Fatal("expected error")
		}
		wantMsg := "keyring file does not exist at \"" + filepath.Join(repo, DefaultKeyringFilename) + "\""
		if got := err.Error(); !strings.Contains(got, wantMsg) {
			t.Fatalf("error should reference the repo-local keyring path, got: %v", got)
		}
	})
}

func TestGlobalKeyringDirPrecedence(t *testing.T) {
	t.Run("env var wins", func(t *testing.T) {
		t.Setenv(EsecKeyringDir, "/custom/dir")
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		if got := GlobalKeyringDir(); got != "/custom/dir" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("xdg respected", func(t *testing.T) {
		t.Setenv(EsecKeyringDir, "")
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		if got := GlobalKeyringDir(); got != "/xdg/esec/keyrings" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("home fallback", func(t *testing.T) {
		t.Setenv(EsecKeyringDir, "")
		t.Setenv("XDG_CONFIG_HOME", "")
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home dir")
		}
		want := filepath.Join(home, ".config", "esec", "keyrings")
		if got := GlobalKeyringDir(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
