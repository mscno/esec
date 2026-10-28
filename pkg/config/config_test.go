package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidatesSharedPreferences(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_CONFIG", "")
	if c, err := Load(); err != nil || c.DefaultFormat != "env" {
		t.Fatalf("defaults: %v", err)
	}
	p := filepath.Join(home, "config.toml")
	for _, bad := range []string{
		"default_format='unknown'", "defaut_format='etoml'",
		"[files]\ncreate='../{env}.{format}'", "[files]\npatterns=[]",
		"[files]\npatterns=['{unknown}.{format}']", "[aliases]\nprod='../production'",
	} {
		if err := os.WriteFile(p, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(); err == nil {
			t.Fatalf("accepted invalid config: %s", bad)
		}
	}
	t.Setenv("ESEC_CONFIG", filepath.Join(home, "missing.toml"))
	if _, err := Load(); err == nil {
		t.Fatal("explicit missing config ignored")
	}
}
