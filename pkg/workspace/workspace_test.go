package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemberRejectsPhysicalAliases(t *testing.T) {
	root := t.TempDir()
	writeTest(t, filepath.Join(root, "esec.toml"), "[workspace.members]\nbackend='backend'\nmobile='BACKEND'\n")
	writeTest(t, filepath.Join(root, "backend/esec.toml"), "project='acme/backend'\n")
	a, err := os.Stat(filepath.Join(root, "backend"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(root, "BACKEND"))
	if err != nil || !os.SameFile(a, b) {
		t.Skip("filesystem treats these paths as distinct")
	}
	i, err := Find(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"backend", "mobile"} {
		if _, err := i.Store(name); err == nil {
			t.Fatal("same physical directory accepted under two aliases")
		}
	}
}

func writeTest(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFindAndMemberBoundaries(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTest(t, filepath.Join(root, "esec.toml"), "[workspace.members]\nmobile='secrets/mobile'\nbackend='backend'\n")
	writeTest(t, filepath.Join(root, "backend/esec.toml"), "project='acme/backend'\n")
	writeTest(t, filepath.Join(root, "secrets/mobile/esec.toml"), "project='acme/mobile'\n")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	i, err := Find(filepath.Join(root, "backend"))
	if err != nil || i.Root != root || i.Names()[0] != "backend" {
		t.Fatal("workspace not found from member", err)
	}
	if path, err := i.Store("mobile"); err != nil || path != filepath.Join(root, "secrets/mobile") {
		t.Fatal("member resolution", err)
	}
	if _, err := i.Store("missing"); err == nil {
		t.Fatal("unknown alias accepted")
	}
	writeTest(t, filepath.Join(root, "secrets/esec.toml"), "project='acme/intermediate'\n")
	if _, err := i.Store("mobile"); err == nil {
		t.Fatal("crossed intermediate store")
	}
	if err := os.Remove(filepath.Join(root, "secrets/esec.toml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "backend/.git"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(filepath.Join(root, "backend")); err == nil {
		t.Fatal("searched across Git boundary")
	}
	if _, err := i.Store("backend"); err == nil {
		t.Fatal("member crossed Git boundary")
	}
}

func TestMemberRejectsMissingSymlinkAndNestedWorkspace(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTest(t, filepath.Join(root, "esec.toml"), "[workspace.members]\nmember='member'\n")
	i, err := Find(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Store("member"); err == nil {
		t.Fatal("missing member accepted")
	}
	outside := t.TempDir()
	writeTest(t, filepath.Join(outside, "esec.toml"), "project='acme/outside'\n")
	if err := os.Symlink(outside, filepath.Join(root, "member")); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Store("member"); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := os.Remove(filepath.Join(root, "member")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "member"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "esec.toml"), filepath.Join(root, "member/esec.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Store("member"); err == nil {
		t.Fatal("symlink manifest accepted")
	}
	if err := os.Remove(filepath.Join(root, "member/esec.toml")); err != nil {
		t.Fatal(err)
	}
	writeTest(t, filepath.Join(root, "member/esec.toml"), "[workspace.members]\nother='other'\n")
	if _, err := i.Store("member"); err == nil {
		t.Fatal("nested workspace accepted")
	}
}
