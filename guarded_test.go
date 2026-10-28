package esec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardedKeyIsExplained(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyring := filepath.Join(dir, "acme_store.keyring")
	if err := os.WriteFile(keyring, []byte("ESEC_GUARD_"+strings.ToUpper(pub)+"=wrapped\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EsecKeyringPath, keyring)
	file := filepath.Join(dir, ".env.prod")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nAPI=ESEC[1:abc]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = DecryptFile(file, dir, "")
	if !errors.Is(err, ErrKeyNotFound) || !strings.Contains(err.Error(), "guarded by your security key") {
		t.Fatalf("want a guarded-key error, got %v", err)
	}
}
