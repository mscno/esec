package commands

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
)

func TestRunLoadsDiscoveredToml(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("requires a POSIX shell")
	}
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_FORMAT", "")
	dir := t.TempDir()
	t.Chdir(dir)
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_PRIVATE_KEY_PROD", priv)
	var encrypted strings.Builder
	if _, err := esec.Encrypt(strings.NewReader("_ESEC_PUBLIC_KEY='"+pub+"'\n[database]\npassword='run-secret'\nport=5432\n"), &encrypted, esec.FileFormatEtoml); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("production.etoml", []byte(encrypted.String()), 0600); err != nil {
		t.Fatal(err)
	}
	get := GetCmd{File: "prod", Key: "database.password"}
	value, getErr := captureOutput(func() error { return get.Run(&cliCtx{Logger: slog.Default()}) })
	if getErr != "" || value != "run-secret" {
		t.Fatalf("TOML get failed: %s", getErr)
	}
	output := filepath.Join(dir, "result")
	c := RunCmd{File: "prod", Command: []string{"sh", "-c", `printf '%s:%s' "$DATABASE__PASSWORD" "$DATABASE__PORT" > "$1"`, "sh", output}}
	if err := c.Run(&cliCtx{Logger: slog.Default()}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output) //nolint:gosec // test-owned output path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "run-secret:5432" {
		t.Fatal("TOML values were not injected")
	}
	// A second candidate must prevent the child from starting.
	if err := os.WriteFile(".env.production", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Run(&cliCtx{Logger: slog.Default()}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity: %v", err)
	}
}
