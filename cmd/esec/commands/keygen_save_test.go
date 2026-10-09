package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
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
