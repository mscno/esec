//nolint:gosec // synthetic secrets and isolated temporary paths only
package commands

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
)

func workspaceFixture(t *testing.T) (string, *cliCtx) {
	t.Helper()
	root, _, _, ctx := standaloneFixture(t)
	for _, name := range []string{"backend", "mobile"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := (&InitCmd{Project: "test/" + name, Env: "dev", Dir: dir, Yes: true}).Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), []byte("[workspace.members]\nmobile='mobile'\nbackend='backend'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return root, ctx
}

func invokeWorkspace(t *testing.T, ctx *cliCtx, args ...string) error {
	t.Helper()
	var c cli
	p, err := kong.New(&c, kong.Vars{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := p.Parse(args)
	if err != nil {
		return err
	}
	if err := c.selectMember(parsed); err != nil {
		return err
	}
	return parsed.Run(ctx)
}

func workspaceTree(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = sha256.Sum256(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func prepareWorkspaceRepair(t *testing.T, root string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, ".env.dev"))
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, ".esec/pending")
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, ".env.dev"), data, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]journalEntry{".env.dev": {Before: digest(data), After: digest(data)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceReadOnlyReportsNeverOpenKeysOrWrite(t *testing.T) {
	root, ctx := workspaceFixture(t)
	before := workspaceTree(t, root)
	t.Setenv("ESEC_AGE_IDENTITY", "invalid-must-never-open")
	for _, command := range []string{"check", "status", "plan", "files"} {
		_, memberErrors := captureOutput(func() error { return invokeWorkspace(t, ctx, "--member", "backend", command, "--json") })
		if memberErrors != "" {
			t.Fatal("member directory command failed", command, memberErrors)
		}
		out, errs := captureOutput(func() error { return invokeWorkspace(t, ctx, command, "--workspace", "--json") })
		if errs != "" {
			t.Fatal(command, errs)
		}
		var report workspaceReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(command, err)
		}
		if len(report.Members) != 2 || report.Members[0].Member != "backend" || report.Members[1].Member != "mobile" {
			t.Fatal("missing or unordered member reports", out)
		}
		if command == "files" && (len(report.Members[0].Files) != 1 || len(report.Members[1].Files) != 1) {
			t.Fatal("missing file metadata", out)
		}
	}
	after := workspaceTree(t, root)
	if len(before) != len(after) {
		t.Fatal("read-only report created files")
	}
	for path, hash := range before {
		if after[path] != hash {
			t.Fatal("read-only report changed file", path)
		}
	}
	for _, args := range [][]string{
		{"--member", "backend", "check", "--workspace"},
		{"--member", "missing", "get", "dev", "TOKEN"},
		{"--member", "backend", "check", "--dir", "mobile"},
		{"--member", "backend", "identity", "list"},
		{"apply", "--workspace"},
		{"init", "--env", "dev", "--yes"},
		{"repair"},
		{"blob", "get", "dev", "TOKEN"},
	} {
		if err := invokeWorkspace(t, ctx, args...); err == nil {
			t.Fatal("unsafe or ambiguous command accepted", args)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".esec")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("root index was mutated")
	}
}

func TestMemberSelectionPreservesCallerPathsAndStoreIsolation(t *testing.T) { //nolint:gocyclo // end-to-end scope, byte preservation, path and child-directory assertions
	root, ctx := workspaceFixture(t)
	if err := os.WriteFile("credential.bin", []byte("exact\x00\xff\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := invokeWorkspace(t, ctx, "--member", "mobile", "blob", "set", "dev", "CREDENTIAL", "--create", "--from", "credential.bin"); err != nil {
		t.Fatal(err)
	}
	if err := invokeWorkspace(t, ctx, "--member", "backend", "blob", "set", "dev", "CREDENTIAL", "--create", "--from", "credential.bin"); err != nil {
		t.Fatal(err)
	}
	show, showErrors := captureOutput(func() error {
		return invokeWorkspace(t, ctx, "--member", "mobile", "secrets", "show", "--file", ".env.dev")
	})
	if showErrors != "" || !strings.Contains(show, "CREDENTIAL") {
		t.Fatal("member-relative secrets path not resolved", showErrors)
	}
	backend, err := esec.ResolveRead(filepath.Join(root, "backend"), "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	mobile, err := esec.ResolveRead(filepath.Join(root, "mobile"), "dev", "")
	if err != nil || backend.PublicKey == mobile.PublicKey {
		t.Fatal("members share an environment key", err)
	}
	out, errs := captureOutput(func() error {
		return invokeWorkspace(t, ctx, "--member", "mobile", "blob", "run", "dev", "--file", "FILE=CREDENTIAL", "--", "sh", "-c", `cat "$FILE"; pwd`)
	})
	if errs != "" || out != "exact\x00\xff\n"+root+"\n" {
		t.Fatalf("caller paths changed: %q %s", out, errs)
	}
	out, errs = captureOutput(func() error {
		return invokeWorkspace(t, ctx, "--member", "mobile", "blob", "get", "dev", "CREDENTIAL", "--out", "restored.bin")
	})
	if errs != "" || out != "" {
		t.Fatal(errs)
	}
	if b, err := os.ReadFile("restored.bin"); err != nil || string(b) != "exact\x00\xff\n" {
		t.Fatal("export path or bytes changed", err)
	}
	if err := invokeWorkspace(t, ctx, "--member", "mobile", "blob", "get", backend.Path, "CREDENTIAL"); err == nil {
		t.Fatal("explicit member allowed another store")
	}
	if err := os.Symlink(backend.Path, filepath.Join(root, "mobile/.env.other")); err != nil {
		t.Fatal(err)
	}
	if err := invokeWorkspace(t, ctx, "--member", "mobile", "decrypt", ".env.other"); err == nil {
		t.Fatal("member followed secret file symlink")
	}
	t.Chdir(filepath.Join(root, "mobile"))
	out, errs = captureOutput(func() error { return invokeWorkspace(t, ctx, "blob", "get", "dev", "CREDENTIAL") })
	if errs != "" || out != "exact\x00\xff\n" {
		t.Fatal("existing store commands broken", errs)
	}
	out, errs = captureOutput(func() error { return invokeWorkspace(t, ctx, "--member", "backend", "inspect", "dev", "--json") })
	if errs != "" || !strings.Contains(out, "test/backend") {
		t.Fatal("selection from another member failed", errs)
	}
}

func TestWorkspaceAggregatesErrorsAndAccessDrift(t *testing.T) { //nolint:gocyclo // integration assertions for reporting, scoped mutation and sibling isolation
	root, ctx := workspaceFixture(t)
	pf, err := projectfile.Load(filepath.Join(root, "backend"))
	if err != nil {
		t.Fatal(err)
	}
	e := pf.Env["dev"]
	e.Recipients = e.Recipients[:1]
	pf.Env["dev"] = e
	if err := pf.Save(filepath.Join(root, "backend")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"check", "--workspace", "--ci", "--json"}, {"status", "--workspace", "--check", "--json"}} {
		var result error
		out, _ := captureOutput(func() error { result = invokeWorkspace(t, ctx, args...); return nil })
		var exit *ExitError
		if !errors.As(result, &exit) || exit.Code != 2 || !strings.Contains(out, "backend") {
			t.Fatal("drift not reported with exit 2", result)
		}
	}
	mobileBefore := workspaceTree(t, filepath.Join(root, "mobile"))
	rootBefore, err := os.ReadFile(filepath.Join(root, "esec.toml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := buildAccessPlan(filepath.Join(root, "backend"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := invokeWorkspace(t, ctx, "--member", "backend", "apply", "--yes", "--plan-hash", p.Hash, "--approve-sensitive"); err != nil {
		t.Fatal("scoped apply failed", err)
	}
	mobileAfter := workspaceTree(t, filepath.Join(root, "mobile"))
	for path, hash := range mobileBefore {
		if mobileAfter[path] != hash {
			t.Fatal("scoped apply modified sibling store")
		}
	}
	rootAfter, err := os.ReadFile(filepath.Join(root, "esec.toml"))
	if err != nil || string(rootBefore) != string(rootAfter) {
		t.Fatal("scoped apply changed index")
	}
	if err := invokeWorkspace(t, ctx, "--member", "backend", "init", "--env", "test", "--yes"); err != nil {
		t.Fatal("scoped init failed", err)
	}
	prepareWorkspaceRepair(t, filepath.Join(root, "backend"))
	if err := invokeWorkspace(t, ctx, "--member", "backend", "repair"); err != nil {
		t.Fatal("scoped repair failed", err)
	}
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), []byte("[workspace.members]\nbackend='backend'\nmobile='mobile'\nbroken='does-not-exist'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var result error
	out, _ := captureOutput(func() error { result = invokeWorkspace(t, ctx, "check", "--workspace", "--json"); return nil })
	var report workspaceReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if result == nil || len(report.Members) != 3 || report.Members[1].Error != "member_missing_or_invalid" || report.Members[2].Check == nil {
		t.Fatal("broken member hid other member reports", out, result)
	}
}
