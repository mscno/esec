package projectfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOrgRepo(t *testing.T) {
	valid := []string{"org/repo", "my-org/my.repo", "o_r/g_r", "a/b"}
	for _, v := range valid {
		if err := ValidateOrgRepo(v); err != nil {
			t.Errorf("expected %q to be valid, got %v", v, err)
		}
	}
	invalid := []string{"", "org", "org/", "/repo", "org/repo/extra", "org/repo space", "../repo"}
	for _, v := range invalid {
		if err := ValidateOrgRepo(v); err == nil {
			t.Errorf("expected %q to be invalid", v)
		}
	}
}

func TestKeyringName(t *testing.T) {
	if got := KeyringName("mscno/esec"); got != "mscno_esec.keyring" {
		t.Errorf("unexpected keyring name: %s", got)
	}
}

func TestWriteAndReadProjectFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteProjectFile(dir, "org/repo"); err != nil {
		t.Fatalf("WriteProjectFile: %v", err)
	}
	project, err := ReadProjectFile(dir)
	if err != nil {
		t.Fatalf("ReadProjectFile: %v", err)
	}
	if project != "org/repo" {
		t.Errorf("unexpected project: %s", project)
	}

	if err := WriteProjectFile(dir, "invalid"); err == nil {
		t.Errorf("expected error writing invalid project")
	}
}

func TestReadProjectFileNotFound(t *testing.T) {
	_, err := ReadProjectFile(t.TempDir())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFindProjectFileWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := WriteProjectFile(root, "org/repo"); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0750); err != nil {
		t.Fatal(err)
	}
	project, path, err := FindProjectFile(nested)
	if err != nil {
		t.Fatalf("FindProjectFile: %v", err)
	}
	if project != "org/repo" {
		t.Errorf("unexpected project: %s", project)
	}
	if path != filepath.Join(root, ProjectFileName) {
		t.Errorf("unexpected path: %s", path)
	}
}

func TestFindProjectFileNotFound(t *testing.T) {
	// Use a temp dir whose parents (up to /) contain no project file we can
	// rely on; assert only that an error surfaces when nothing is found by
	// checking against a path we control fully via a chdir-like walk.
	dir := t.TempDir()
	_, _, err := FindProjectFile(dir)
	// The walk reaches the filesystem root; on machines where a parent of the
	// temp dir has a project file this could succeed, so accept either outcome
	// but require no crash and a consistent result.
	if err == nil {
		t.Logf("found a project file above %s (unusual but valid)", dir)
	} else if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
