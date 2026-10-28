package esec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// A machine with only an age identity reads secrets: the key is sealed in
// the repository to its recipient.
func TestDecryptWithSealedKey(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
	t.Setenv(EsecKeyringPath, "")
	t.Setenv("ESEC_CONFIG", "")
	f := &projectfile.File{Project: "acme/store"}
	f.SetEnv("prod", pub)
	e := f.Env["prod"]
	e.Guard = projectfile.GuardTouch
	f.Env["prod"] = e
	if err := f.Save(repo); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repo, ".env.prod")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nAPI=sk_live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptFileInPlace(file); err != nil {
		t.Fatal(err)
	}
	ci, _ := age.GenerateX25519Identity()
	data, err := seal.Seal(seal.Payload{Project: "acme/store", Env: "prod", Guard: "touch", Private: priv}, ci.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(repo, "prod", data); err != nil {
		t.Fatal(err)
	}

	// No identity: the error says the key is sealed, and guarded.
	t.Setenv(seal.EnvIdentity, "")
	_, err = DecryptFile(file, repo, "")
	if !errors.Is(err, ErrKeyNotFound) || !strings.Contains(err.Error(), "sealed in") || !strings.Contains(err.Error(), "touch") {
		t.Fatalf("want a sealed-key error, got %v", err)
	}
	// The machine's identity opens it.
	t.Setenv(seal.EnvIdentity, ci.String())
	out, err := DecryptFile(file, repo, "")
	if err != nil || !strings.Contains(string(out), "API=sk_live") {
		t.Fatalf("decrypt: %s %v", out, err)
	}
	// Another identity does not.
	other, _ := age.GenerateX25519Identity()
	t.Setenv(seal.EnvIdentity, other.String())
	if _, err := DecryptFile(file, repo, ""); err == nil {
		t.Fatal("decrypted with an identity that is not a reader")
	}
}
