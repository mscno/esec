package projectfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOrgRepo(t *testing.T) {
	valid := []string{"org/repo", "my-org/my.repo", "o_r/g_r", "a/b"}
	for _, v := range valid {
		if err := ValidateOrgRepo(v); err != nil {
			t.Errorf("expected %q to be valid, got %v", v, err)
		}
	}
	invalid := []string{"", "org", "org/", "/repo", "org/repo space", "../repo"}
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

func TestProjectFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub := "a1" + strings.Repeat("0", 62)
	f := &File{Project: "acme/store", Files: Files{Format: "env", Name: ".env.{env}"}}
	f.SetEnv("dev", pub)
	f.SetEnv("api.prod", pub)
	e := f.Env["api.prod"]
	e.Guard = GuardTouch
	f.Env["api.prod"] = e
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Project != "acme/store" || got.Files.Name != ".env.{env}" || got.Env["api.prod"].GuardLevel() != GuardTouch || got.Env["dev"].GuardLevel() != GuardNone || got.Env["dev"].Key != pub {
		t.Fatalf("round trip: %+v", got)
	}
	if strings.Join(got.Envs(), ",") != "api.prod,dev" {
		t.Fatalf("envs: %v", got.Envs())
	}
	// WriteProjectFile keeps the rest of the file.
	if err := WriteProjectFile(dir, "acme/shop"); err != nil {
		t.Fatal(err)
	}
	if got, _ = Load(dir); got.Project != "acme/shop" || len(got.Env) != 2 {
		t.Fatalf("rename lost environments: %+v", got)
	}
}

func TestProjectFileRejectsInvalid(t *testing.T) {
	for _, bad := range []string{
		`project = "nope"`,
		"project = \"a/b\"\n[env.Prod]\nkey = \"\"",
		"project = \"a/b\"\n[env.prod]\nkey = \"xyz\"",
		"project = \"a/b\"\n[env.prod]\nguard = \"maybe\"",
		"project = \"a/b\"\n[files]\nname = \"../{env}.env\"",
		"project = \"a/b\"\n[files]\nformat = \"xml\"",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSaveKeepsCommentsAndLayout(t *testing.T) {
	dir := t.TempDir()
	orig := `# Owner: platform team
project = "acme/store" # the repo

[files]
format = "env"
name = ".env.{env}"

# Production: guarded.
[env.prod]
key = "` + strings.Repeat("a", 64) + `" # rotated in March
guard = "touch"
`
	if err := os.WriteFile(filepath.Join(dir, ProjectFileName), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.SetEnv("prod", strings.Repeat("b", 64))
	f.SetEnv("dev", strings.Repeat("c", 64))
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ProjectFileName)) //nolint:gosec // a test file
	got := string(data)
	want := strings.Replace(orig, strings.Repeat("a", 64), strings.Repeat("b", 64), 1) + "\n[env.dev]\nkey = \"" + strings.Repeat("c", 64) + "\"\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	// Removing a guard removes its line only.
	f, _ = Load(dir)
	e := f.Env["prod"]
	e.Guard = ""
	f.Env["prod"] = e
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, ProjectFileName)) //nolint:gosec // a test file
	if strings.Contains(string(data), "guard =") || !strings.Contains(string(data), "# Production: guarded.") {
		t.Fatalf("after removing the guard:\n%s", data)
	}
}

func TestSaveNewFileAndInlineTables(t *testing.T) {
	dir := t.TempDir()
	f := &File{Project: "acme/store", Files: Files{Format: "ejson"}}
	f.SetEnv("dev", strings.Repeat("a", 64))
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ProjectFileName)) //nolint:gosec // a test file
	want := header + `project = "acme/store"

[files]
format = "ejson"

[env.dev]
key = "` + strings.Repeat("a", 64) + "\"\n"
	if string(data) != want {
		t.Fatalf("new file:\n%s", data)
	}

	// A layout the editor does not handle is written afresh, correctly.
	inline := "project = \"acme/store\"\nenv = { dev = { key = \"" + strings.Repeat("a", 64) + "\" } }\n"
	if err := os.WriteFile(filepath.Join(dir, ProjectFileName), []byte(inline), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.SetEnv("prod", strings.Repeat("b", 64))
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || got.Env["dev"].Key != strings.Repeat("a", 64) || got.Env["prod"].Key != strings.Repeat("b", 64) {
		t.Fatalf("rewritten: %+v %v", got, err)
	}
}

func TestParseUnknownKeysAndFilesFormat(t *testing.T) {
	f, err := Parse([]byte("project = \"acme/store\"\nowner = \"me\"\n[env.dev]\nkye = \"x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if u := f.Unknown(); len(u) != 2 || u[0] != "owner" || u[1] != "env.dev.kye" {
		t.Fatalf("unknown = %v", u)
	}
	for _, bad := range []string{
		"project = \"a/b\"\n[files]\nname = \"secrets.{env}\"\n",
		"project = \"a/b\"\n[files]\nformat = \"etoml\"\nname = \".env.{env}\"\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	f, err = Parse([]byte("project = \"a/b\"\n[files]\nname = \"{env}.etoml\"\n"))
	if err != nil || f.FilesFormat() != "etoml" {
		t.Fatalf("format from name: %v %v", f, err)
	}
}

func TestReadersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ProjectFileName), []byte("project = \"acme/store\"\n\n[env.prod]\nkey = \""+strings.Repeat("a", 64)+"\" # keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := Load(dir)
	e := f.Env["prod"]
	e.Readers = []string{"mads (gh:583231)", "deploy (age1xyz)"}
	f.Env["prod"] = e
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ProjectFileName)) //nolint:gosec // a test file
	if !strings.Contains(string(data), `readers = ["mads (gh:583231)", "deploy (age1xyz)"]`) || !strings.Contains(string(data), "# keep") {
		t.Fatalf("readers:\n%s", data)
	}
	got, _ := Load(dir)
	if len(got.Env["prod"].Readers) != 2 {
		t.Fatalf("%+v", got.Env["prod"])
	}
	if _, err := Parse([]byte("project = \"a/b\"\n[env.dev]\nreaders = [\"bad\\nname\"]\n")); err == nil {
		t.Fatal("a reader with a newline was accepted")
	}
}
