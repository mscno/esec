package commands

import (
	"os"
	"strings"
	"testing"
)

// A project that requires a newer esec is refused before the command runs;
// a development build and a directory with no project are not.
func TestCheckRequires(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/esec.toml", []byte("project = \"acme/store\"\nrequires = \">= 99.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := checkRequires("decrypt <file>", "v0.14.0"); err == nil || !strings.Contains(err.Error(), "requires esec >= 99.0") {
		t.Fatalf("old esec: %v", err)
	}
	if err := checkRequires("decrypt <file>", "dev"); err != nil {
		t.Fatalf("dev build: %v", err)
	}
	if err := checkRequires("capabilities", "v0.14.0"); err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	t.Chdir(t.TempDir())
	if err := checkRequires("decrypt <file>", "v0.14.0"); err != nil {
		t.Fatalf("no project: %v", err)
	}
}
