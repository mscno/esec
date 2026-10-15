package esec

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/keyringfile"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/secretstore"
)

func TestSealedGlobalKeyring(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	want, _ := hex.DecodeString(testPrivateKeyHex)
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	globalDir := filepath.Join(home, "keyrings")
	t.Setenv(EsecKeyringDir, globalDir)

	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(globalDir, "org_repo.keyring")
	store, err := secretstore.Default()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keyringfile.Codec{Store: store}.Encode(keyringPath, []byte("ESEC_PRIVATE_KEY_DEV="+testPrivateKeyHex+"\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	writeKeyring(t, keyringPath, string(sealed))

	key, err := findPrivateKeyForData(repo, "dev", "", nil, "", logger)
	if err != nil {
		t.Fatalf("findPrivateKey: %v", err)
	}
	if key != [32]byte(want) {
		t.Fatalf("unexpected key: %x", key)
	}

	// A plain keyring next to sealed ones keeps working.
	writeKeyring(t, filepath.Join(globalDir, DefaultKeyringBasename), "ESEC_PRIVATE_KEY_QA="+testPrivateKeyHex+"\n")
	if _, err := findPrivateKeyForData(repo, "qa", "", nil, "", logger); err != nil {
		t.Fatalf("plain keyring beside a sealed one: %v", err)
	}

	// Without the cache key the failure must name the sealed file, not claim
	// the key is missing.
	if err := store.Delete(keyringfile.CacheKeyName); err != nil {
		t.Fatal(err)
	}
	_, err = findPrivateKeyForData(repo, "dev", "", nil, "", logger)
	if err == nil || !errors.Is(err, keyringfile.ErrCacheKey) || !strings.Contains(err.Error(), "sealed keyring") {
		t.Fatalf("missing cache key not reported clearly: %v", err)
	}
	if _, err := sniffFromKeyring(logger, repo, ""); err == nil {
		t.Fatal("sniffing a sealed keyring without its key must fail")
	}
}

func TestSealedKeyringIsBoundToItsFileName(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	globalDir := filepath.Join(home, "keyrings")
	t.Setenv(EsecKeyringDir, globalDir)
	repo := t.TempDir()
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(globalDir, "org_other.keyring")
	sealed, err := keyringfile.Codec{}.Encode(other, []byte("ESEC_PRIVATE_KEY_DEV="+testPrivateKeyHex+"\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	// Copy another project's sealed keyring over this project's file name.
	writeKeyring(t, filepath.Join(globalDir, "org_repo.keyring"), string(sealed))
	if _, err := findPrivateKeyForData(repo, "dev", "", nil, "", logger); err == nil {
		t.Fatal("a keyring sealed for another file was accepted")
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("test wrote unexpected file")
	}
}
