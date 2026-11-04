package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// guardedRepo makes a repository whose prod key is guarded and sealed to
// someone else, and changes into it.
func guardedRepo(t *testing.T, guard string) {
	t.Helper()
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
	t.Setenv(esec.EsecKeyringPath, "")
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv(seal.EnvIdentity, "")
	t.Setenv("ESEC_PRIVATE_KEY_PROD", "") // restored after the test
	if err := os.Unsetenv("ESEC_PRIVATE_KEY_PROD"); err != nil {
		t.Fatal(err)
	}
	f := &projectfile.File{Project: "acme/store"}
	f.SetEnv("prod", pub)
	e := f.Env["prod"]
	e.Guard = guard
	f.Env["prod"] = e
	if err := f.Save(repo); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repo, ".env.prod")
	if err := os.WriteFile(file, []byte("ESEC_PUBLIC_KEY="+pub+"\nAPI=sk_live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := esec.EncryptFileInPlace(file); err != nil {
		t.Fatal(err)
	}
	someone, _ := age.GenerateX25519Identity()
	data, err := seal.Seal(seal.Payload{Project: "acme/store", Env: "prod", Guard: guard, Private: priv}, someone.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(repo, "prod", data); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
}

func TestGuardedReadsRequireOfflineCredentialForNamesAndFiles(t *testing.T) {
	guardedRepo(t, projectfile.GuardTouch)
	ctx := &cliCtx{Logger: slog.New(slog.DiscardHandler)}
	for _, input := range []string{"prod", ".env.prod"} {
		got, msg := captureOutput(func() error { return (&DecryptCmd{File: input, KeyDir: "."}).Run(ctx) })
		if got != "" || !strings.Contains(msg, "legacy_guard_requires_migration") {
			t.Fatalf("unexpected guarded read: %q %s", got, msg)
		}
		got, msg = captureOutput(func() error { return (&GetCmd{File: input, Key: "API", KeyDir: "."}).Run(ctx) })
		if got != "" || !strings.Contains(msg, "legacy_guard_requires_migration") {
			t.Fatalf("unexpected guarded get: %q %s", got, msg)
		}
	}
}
