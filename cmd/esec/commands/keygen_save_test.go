package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/keyringfile"
	"github.com/mscno/esec/pkg/secretstore"
)

func TestKeygenSaveRetainsOldKeysAndDecrypts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_KEYRING_DIR", dir)
	c := KeygenCmd{Save: true, Env: "api.prod", Project: "org/repo"}
	ctx := &cliCtx{Logger: slog.Default()}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "org_repo.keyring")
	entries, err := godotenv.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries["ESEC_PRIVATE_KEY_API_PROD"] == "" {
		t.Fatal("key aliases missing")
	}
	old := entries["ESEC_PRIVATE_KEY_API_PROD"]
	if err := c.Run(ctx); err == nil {
		t.Fatal("existing environment overwritten")
	}
	c.Env = "dev"
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err = godotenv.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if entries["ESEC_PRIVATE_KEY_API_PROD"] != old || len(entries) != 4 {
		t.Fatal("old keys lost")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("keyring permissions")
	}
	if esec.GlobalKeyringDir() != dir {
		t.Fatal("wrong store")
	}
}

func TestKeygenSaveKeepsSealedKeyringSealed(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "keyrings")
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_KEYRING_DIR", dir)
	t.Setenv(secretstore.EnvBackend, secretstore.BackendFile)
	if err := secretstore.SaveConfig(&secretstore.Config{Backend: secretstore.BackendFile, SealKeyrings: true}); err != nil {
		t.Fatal(err)
	}
	ctx := &cliCtx{Logger: slog.Default()}
	c := KeygenCmd{Save: true, Env: "dev", Project: "org/repo"}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "org_repo.keyring")
	data, err := os.ReadFile(p) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !keyringfile.IsSealed(data) {
		t.Fatal("new keyring not sealed although seal_keyrings is set")
	}
	c.Env = "prod"
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(p) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	entries, err := keyringfile.Parse(p, data)
	if err != nil {
		t.Fatal(err)
	}
	if entries["ESEC_PRIVATE_KEY_DEV"] == "" || entries["ESEC_PRIVATE_KEY_PROD"] == "" || !keyringfile.IsSealed(data) {
		t.Fatal("sealed keyring lost entries or was unsealed on update")
	}

	// A plain keyring stays plain even when new keyrings are sealed.
	plainPath := filepath.Join(dir, "org_plain.keyring")
	if err := os.WriteFile(plainPath, []byte("# ESEC_PROJECT=org/plain\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c = KeygenCmd{Save: true, Env: "dev", Project: "org/plain"}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(plainPath) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if keyringfile.IsSealed(data) {
		t.Fatal("existing plain keyring was sealed implicitly")
	}
}

func TestCapabilities(t *testing.T) {
	if err := (&CapabilitiesCmd{}).Run(&cliCtx{}); err != nil {
		t.Fatal(err)
	}
}
