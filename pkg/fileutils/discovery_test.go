package fileutils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDiscovery(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	dir := t.TempDir()
	if _, _, err := Resolve(dir, "prod", ""); err == nil || !strings.Contains(err.Error(), "no secrets file") {
		t.Fatalf("missing file: %v", err)
	}
	p := filepath.Join(dir, "production.etoml")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, f, err := Resolve(dir, "prod", "")
	if err != nil || got != p || f != Etoml {
		t.Fatalf("alias discovery: %s %s %v", got, f, err)
	}
	if Environment(p) != "production" {
		t.Fatal("suffix name lost its environment")
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(dir, "prod", ""); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous: %v", err)
	}
	if got, _, err := Resolve(dir, "prod", "etoml"); err != nil || got != p {
		t.Fatalf("format filter: %s %v", got, err)
	}
	if got, _, err := Resolve(dir, "production.etoml", "env"); err != nil || got != p {
		t.Fatalf("explicit file: %s %v", got, err)
	}
	if _, _, err := Resolve(dir, "../prod", ""); err == nil {
		t.Fatal("accepted environment traversal")
	}
}

func TestResolveConfiguredPatterns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_CONFIG", "")
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("default_format='etoml'\n[files]\npatterns=['secrets/{env}.{format}']\n[aliases]\nprod='live'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "secrets/live.etoml")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := Resolve(dir, "prod", ""); err != nil || got != p {
		t.Fatalf("configured discovery: %s %v", got, err)
	}
}

func TestResolveProjectFileNaming(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	dir := t.TempDir()
	toml := "project = \"acme/store\"\n[files]\nformat = \"etoml\"\nname = \"secrets/{env}.etoml\"\n"
	if err := os.WriteFile(filepath.Join(dir, "esec.toml"), []byte(toml), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0750); err != nil {
		t.Fatal(err)
	}
	// A file the machine's defaults would find is not the project's file.
	if err := os.WriteFile(filepath.Join(dir, ".env.dev"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(dir, "dev", ""); err == nil {
		t.Fatal("found a file the project does not name")
	}
	p := filepath.Join(dir, "secrets", "dev.etoml")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, f, err := Resolve(dir, "dev", "")
	if err != nil || got != p || f != Etoml {
		t.Fatalf("project naming: %s %s %v", got, f, err)
	}
}
