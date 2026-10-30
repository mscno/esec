package commands

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/projectfile"
)

func isolateSetup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	home := t.TempDir()
	t.Setenv("ESEC_VAULT_HOME", home)
	t.Setenv("ESEC_KEYRING_DIR", filepath.Join(home, "keyrings"))
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_KEYRING_PATH", "")
	origI, origL := setupInteractive, lookVault
	setupInteractive = func() bool { return false }
	lookVault = func() (string, error) { return "", errors.New("not installed") }
	t.Cleanup(func() {
		setupInteractive = origI
		lookVault = origL
	})
	return dir
}

func setupCtx() *cliCtx {
	return &cliCtx{Logger: slog.New(slog.DiscardHandler)}
}

func TestSetupNamesTheMissingFlag(t *testing.T) {
	isolateSetup(t)
	err := (&SetupCmd{Env: "dev", Format: "env"}).Run(setupCtx())
	if code, ok := commandExit(err); !ok || code != 80 || !strings.Contains(err.Error(), "--project") {
		t.Fatalf("missing project: %v", err)
	}
	err = (&SetupCmd{Project: "acme/store", Format: "env"}).Run(setupCtx())
	if code, ok := commandExit(err); !ok || code != 80 || !strings.Contains(err.Error(), "--env") {
		t.Fatalf("missing env: %v", err)
	}
	err = (&SetupCmd{Project: "acme/store", Env: "dev,staging,production"}).Run(setupCtx())
	if code, ok := commandExit(err); !ok || code != 80 || !strings.Contains(err.Error(), "--format") {
		t.Fatalf("missing format: %v", err)
	}
	err = (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env"}).Run(setupCtx())
	if code, ok := commandExit(err); !ok || code != 80 || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("missing yes: %v", err)
	}
}

func TestSetupLocalCreatesFilesAndKeepsKeysOutOfOutput(t *testing.T) {
	dir := isolateSetup(t)
	cmd := &SetupCmd{
		Project: "acme/store",
		Env:     "dev,staging,production",
		Format:  "env",
		Yes:     true,
		Local:   true,
	}
	out, errOut, err := captureAll(func() error { return cmd.Run(setupCtx()) })
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	f, err := projectfile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.Project != "acme/store" || f.Files.Format != "env" || f.Files.Name != ".env.{env}" {
		t.Fatalf("esec.toml = %+v", f)
	}
	assertLocalEnvs(t, dir, f)
	ring, err := godotenv.Read(keyringPath("acme/store"))
	if err != nil {
		t.Fatal(err)
	}
	priv := ring["ESEC_PRIVATE_KEY_PRODUCTION"]
	if priv == "" || ring["ESEC_PRIVATE_KEY_DEV"] == "" || ring["ESEC_PRIVATE_KEY_"+strings.ToUpper(f.Env["dev"].Key)] == "" {
		t.Fatal("keyring missing entries")
	}
	if strings.Contains(out+errOut, priv) || strings.Contains(out+errOut, ring["ESEC_PRIVATE_KEY_DEV"]) {
		t.Fatal("private key printed")
	}
	ignore, err := os.ReadFile(filepath.Join(dir, ".gitignore")) //nolint:gosec // test temp dir
	if err != nil || !strings.Contains(string(ignore), ".esec-keyring") {
		t.Fatalf("gitignore: %v %q", err, ignore)
	}
	if !strings.Contains(errOut, "not reserved") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestSetupLocalDoesNotOverwrite(t *testing.T) {
	dir := isolateSetup(t)
	if err := os.WriteFile(filepath.Join(dir, ".env.dev"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true, Local: true}).Run(setupCtx())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, ".env.dev")) //nolint:gosec // test temp dir
	if err != nil || string(body) != "keep\n" {
		t.Fatalf("file changed: %v %q", err, body)
	}
	if _, err := os.Stat(filepath.Join(dir, "esec.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("esec.toml written after a refused file")
	}
}

func TestSetupAddDoesNotRotate(t *testing.T) {
	dir := isolateSetup(t)
	ctx := setupCtx()
	if err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true, Local: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := projectfile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	dev := before.Env["dev"].Key
	if err := (&SetupCmd{Add: true, Env: "ops", Yes: true, Local: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := projectfile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Env["dev"].Key != dev || after.Env["ops"].Key == "" || after.Env["ops"].Key == dev {
		t.Fatalf("keys changed: before %s after %+v", dev, after.Env)
	}
	if after.Project != "acme/store" || after.Files.Format != "env" {
		t.Fatalf("project changed: %+v", after)
	}
	ring, err := godotenv.Read(keyringPath("acme/store"))
	if err != nil {
		t.Fatal(err)
	}
	if ring["ESEC_PRIVATE_KEY_DEV"] == "" || ring["ESEC_PRIVATE_KEY_OPS"] == "" {
		t.Fatal(ring)
	}
}

func TestSetupRefusesExistingProjectWithoutAdd(t *testing.T) {
	isolateSetup(t)
	ctx := setupCtx()
	if err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true, Local: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	err := (&SetupCmd{Project: "acme/store", Env: "ops", Format: "env", Yes: true, Local: true}).Run(ctx)
	if code, ok := commandExit(err); !ok || code != 80 || !strings.Contains(err.Error(), "--add") {
		t.Fatal(err)
	}
}

func TestSetupEncryptsExampleTemplate(t *testing.T) {
	dir := isolateSetup(t)
	if err := os.WriteFile(filepath.Join(dir, "example.env"), []byte("DATABASE_URL=postgres://localhost/db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true, Local: true}).Run(setupCtx()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, ".env.dev")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "postgres://") || !strings.Contains(text, "ESEC[") || !strings.Contains(text, "ESEC_PUBLIC_KEY=") {
		t.Fatalf("template not encrypted: %s", text)
	}
}

func TestSetupRefusesGuardWithoutVault(t *testing.T) {
	isolateSetup(t)
	err := (&SetupCmd{
		Project: "acme/store", Env: "production", Format: "env",
		Guard: []string{"production=touch"}, Yes: true, Local: true,
	}).Run(setupCtx())
	if err == nil || !strings.Contains(err.Error(), "guard") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat("esec.toml"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("wrote a project after refusing guard")
	}
}

func TestSetupVaultInitAndShare(t *testing.T) {
	dir := isolateSetup(t)
	var calls [][]string
	stubVault(t, func(gotDir string, _ time.Duration, args ...string) ([]byte, []byte, int, error) {
		if gotDir != dir {
			t.Errorf("vault dir %s, want %s", gotDir, dir)
		}
		calls = append(calls, append([]string{}, args...))
		switch {
		case len(args) > 0 && (args[0] == "status" || args[0] == "org" || args[0] == "security-keys"):
			return []byte(`{"signed_in":true,"server":"https://vault.example","login":"mads","github_id":1,"identity":"mads (gh:1)","personal":"acme","keys":[{"id":"yk"}]}`), nil, 0, nil
		case len(args) >= 2 && args[0] == "project" && args[1] == "check":
			return []byte(`{"project":"acme/store","available":true,"relation":"available","namespace":{"name":"acme","kind":"organisation","you_may_create":true}}`), nil, 0, nil
		case len(args) >= 2 && args[0] == "project" && args[1] == "init":
			return []byte(`{"synced":false}`), nil, 0, nil
		case len(args) >= 1 && args[0] == "sync":
			return []byte(`{}`), nil, 0, nil
		case len(args) >= 1 && args[0] == "share":
			return []byte(`{}`), nil, 0, nil
		default:
			return nil, []byte("unexpected"), 1, nil
		}
	})
	err := (&SetupCmd{
		Project: "acme/store",
		Env:     "dev,production",
		Format:  "env",
		Guard:   []string{"production=touch"},
		With:    []string{"alice"},
		Yes:     true,
	}).Run(setupCtx())
	if err != nil {
		t.Fatal(err)
	}
	assertVaultCalls(t, dir, calls)
	if _, err := os.Stat(filepath.Join(dir, "esec.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("local esec.toml written on the vault path")
	}
}

func TestSetupRefusesTakenName(t *testing.T) {
	dir := isolateSetup(t)
	stubVault(t, func(_ string, _ time.Duration, args ...string) ([]byte, []byte, int, error) {
		if len(args) >= 2 && args[0] == "project" && args[1] == "check" {
			return []byte(`{"project":"acme/store","available":false,"relation":"taken","namespace":{"name":"acme","kind":"organisation","you_may_create":true,"reason":"already used"}}`), nil, 0, nil
		}
		if len(args) >= 2 && args[0] == "project" && args[1] == "init" {
			t.Fatal("init ran after a taken name")
		}
		return []byte(`{"signed_in":true,"server":"https://vault.example","login":"mads"}`), nil, 0, nil
	})
	err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true}).Run(setupCtx())
	if err == nil || !strings.Contains(err.Error(), "taken") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "esec.toml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("wrote files for a taken name")
	}
}

func TestSetupOldVaultIsNotTreatedAsFree(t *testing.T) {
	dir := isolateSetup(t)
	stubVault(t, func(_ string, _ time.Duration, args ...string) ([]byte, []byte, int, error) {
		if len(args) >= 2 && args[0] == "project" && args[1] == "check" {
			return nil, []byte("unexpected argument check"), 80, nil
		}
		if len(args) > 0 && args[0] == "project" {
			t.Fatal("init ran without a name check")
		}
		return []byte(`{"signed_in":true,"server":"https://vault.example","login":"mads"}`), nil, 0, nil
	})
	err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true}).Run(setupCtx())
	if err == nil || !strings.Contains(err.Error(), "cannot check") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "esec.toml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("wrote files when the name was not checked")
	}
}

func TestSetupStopsWhenVaultIsMissing(t *testing.T) {
	isolateSetup(t)
	err := (&SetupCmd{Project: "acme/store", Env: "dev", Format: "env", Yes: true}).Run(setupCtx())
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatal(err)
	}
	if hintText(err) == "" || !strings.Contains(hintText(err), "--local") {
		t.Fatalf("hint = %q", hintText(err))
	}
}

func TestParseGuardsAndReaders(t *testing.T) {
	guards, err := parseGuards([]string{"production=touch", "ops=none"})
	if err != nil || guards["production"] != "touch" || guards["ops"] != "none" {
		t.Fatal(err, guards)
	}
	if _, err := parseGuards([]string{"production"}); err == nil {
		t.Fatal("guard without a level accepted")
	}
	readers, err := parseReaders([]string{"alice, bob", "group acme/backend"})
	if err != nil || len(readers) != 3 {
		t.Fatal(err, readers)
	}
	if _, err := parseReaders([]string{"not a login"}); err == nil {
		t.Fatal("bad reader accepted")
	}
}

func TestParseStatusReadsVaultServer(t *testing.T) {
	v := &vaultInfo{}
	parseStatus(v, []byte(`{"identity":"fingerprint","signed_in":true,"server":"https://vault.example","login":"mads","github_id":7,"reader":"mads (gh:7)","vault_server":{"server":"https://nested","login":"other"},"namespaces":[{"name":"acme","kind":"team","you_may_create":true}]}`))
	if !v.SignedIn || v.Login != "mads" || v.Identity != "mads (gh:7)" || v.Server != "https://vault.example" {
		t.Fatalf("%+v", v)
	}
	if len(v.Namespaces) != 1 || v.Namespaces[0].Name != "acme" {
		t.Fatal(v.Namespaces)
	}
	onlyNested := &vaultInfo{}
	parseStatus(onlyNested, []byte(`{"identity":"ab:cd","vault_server":{"server":"https://vault.example","login":"mads"}}`))
	if !onlyNested.SignedIn || onlyNested.Login != "mads" || onlyNested.Identity != "" {
		t.Fatalf("nested status: %+v", onlyNested)
	}
}

func TestProjectCheckAllows(t *testing.T) {
	ok, err := parseProjectCheck([]byte(`{"available":true,"relation":"available","namespace":{"name":"acme","you_may_create":true}}`))
	if err != nil || ok.allows(false) != nil {
		t.Fatal(err, ok.allows(false))
	}
	yours, err := parseProjectCheck([]byte(`{"relation":"yours","project":"acme/store"}`))
	if err != nil || yours.allows(false) == nil || yours.allows(true) != nil {
		t.Fatal(yours.allows(false), yours.allows(true))
	}
	if _, err := parseProjectCheck([]byte(`{"error":"nope"}`)); err != nil {
		t.Fatal(err)
	}
	incomplete, err := parseProjectCheck([]byte(`{}`))
	if err != nil || incomplete.allows(false) == nil {
		t.Fatal("empty check treated as free")
	}
}

func assertLocalEnvs(t *testing.T, dir string, f *projectfile.File) {
	t.Helper()
	for _, env := range []string{"dev", "staging", "production"} {
		if f.Env[env].Key == "" || f.Env[env].Guard != "" || len(f.Env[env].Readers) != 0 {
			t.Fatalf("env %s = %+v", env, f.Env[env])
		}
		body, err := os.ReadFile(filepath.Join(dir, ".env."+env)) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "ESEC_PUBLIC_KEY="+f.Env[env].Key) {
			t.Fatalf("%s = %q", env, body)
		}
	}
}

func assertVaultCalls(t *testing.T, dir string, calls [][]string) {
	t.Helper()
	var init, share, sync bool
	want := []string{"project", "init", "acme/store", "--env", "dev,production", "--format", "env", "--dir", dir, "--json", "--guard", "production=touch"}
	for _, args := range calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "ESEC_PRIVATE") || strings.Contains(joined, "AGE-SECRET") {
			t.Fatalf("secret in vault args: %v", args)
		}
		if len(args) >= 2 && args[0] == "project" && args[1] == "init" {
			init = true
			if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("init args %v", args)
			}
		}
		if len(args) > 0 && args[0] == "share" {
			share = true
			if !strings.Contains(joined, "--with alice") || !strings.Contains(joined, "--yes") {
				t.Fatalf("share args %v", args)
			}
		}
		if len(args) > 0 && args[0] == "sync" {
			sync = true
		}
	}
	if !init || !share || !sync {
		t.Fatalf("calls = %v", calls)
	}
}

func stubVault(t *testing.T, fn func(dir string, timeout time.Duration, args ...string) ([]byte, []byte, int, error)) {
	t.Helper()
	origL, origR := lookVault, runVault
	lookVault = func() (string, error) { return "esec-vault", nil }
	runVault = fn
	t.Cleanup(func() {
		lookVault = origL
		runVault = origR
	})
}

func captureAll(f func() error) (string, string, error) {
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	var stdout, stderr strings.Builder
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = io.Copy(&stdout, rOut) })
	wg.Go(func() { _, _ = io.Copy(&stderr, rErr) })
	err := f()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = wOut.Close()
	_ = wErr.Close()
	wg.Wait()
	return stdout.String(), stderr.String(), err
}
