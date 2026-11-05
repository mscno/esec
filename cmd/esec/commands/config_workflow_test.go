//nolint:gosec // isolated temporary paths contain synthetic fixtures only
package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
)

func configureRun(t *testing.T, root string) {
	t.Helper()
	p, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	p.Run.EnvironmentVariable = "APP_ENV"
	e := p.Env["dev"]
	e.Run.PreserveEnv = []string{"DATABASE_URL"}
	p.Env["dev"] = e
	if err := p.Save(root); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationPreviewsNeverOpenIdentities(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	configureRun(t, root)
	t.Chdir(root)
	t.Setenv("ESEC_AGE_IDENTITY", "invalid-identity-must-never-be-read")
	t.Setenv("DATABASE_URL", "sensitive-inherited-value")
	t.Setenv("APP_ENV", "")
	if err := os.Unsetenv("APP_ENV"); err != nil {
		t.Fatal(err)
	}
	output, errs := captureOutput(func() error {
		return (&RunCmd{File: "dev", Explain: true, JSON: true, KeyFromStdin: true, Command: []string{"nonexistent-must-not-run"}}).Run(ctx)
	})
	if errs != "" {
		t.Fatal(errs)
	}
	var plan runPlan
	if err := json.Unmarshal([]byte(output), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.EnvironmentVariable != "APP_ENV" || len(plan.Variables) != 3 {
		t.Fatal(output)
	}
	if !strings.Contains(output, "inherited_override") || strings.Contains(output, "sensitive-inherited-value") || strings.Contains(output, "synthetic-dev") {
		t.Fatal("preview leaked values or missed override")
	}
	if r := checkProject(root); len(r.Findings) != 0 {
		t.Fatalf("check: %+v", r)
	}
	// No private keys are needed to compare a second encrypted file.
	content, err := os.ReadFile(filepath.Join(root, ".env.dev"))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), ".env.test")
	if err := os.WriteFile(other, content, 0600); err != nil {
		t.Fatal(err)
	}
	diff, err := compareKeys([]string{"dev", other})
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rows) != 2 || !diff.Rows[0].Present[0] || !diff.Rows[0].Present[1] {
		t.Fatal("bad key union")
	}
	if _, err := compareKeys([]string{"dev", ".env.dev"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	t.Setenv("APP_ENV", "secret-conflict-do-not-print")
	_, _, err = (&RunCmd{File: "dev"}).plan()
	if err == nil || strings.Contains(err.Error(), "secret-conflict") {
		t.Fatal("binding not enforced safely")
	}
}

func TestRunConfiguredEmptyOverrideAndBinding(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	configureRun(t, root)
	t.Chdir(root)
	t.Setenv("APP_ENV", "dev")
	t.Setenv("DATABASE_URL", "")
	output, errs := captureOutput(func() error {
		return (&RunCmd{File: "dev", Command: []string{"sh", "-c", `printf '%s:%s' "$APP_ENV" "$DATABASE_URL"`}}).Run(ctx)
	})
	if errs != "" || output != "dev:" {
		t.Fatalf("got %q %q", output, errs)
	}
}

func TestCheckReportsPlaintextMalformedCiphertextAndDrift(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	path := filepath.Join(root, ".env.dev")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"LEAK=sensitive-value-never-echoed\n", "BAD=ESEC[1:broken:broken:broken]\n"} {
		if err := os.WriteFile(path, append(bytes.Clone(original), []byte(line)...), 0600); err != nil {
			t.Fatal(err)
		}
		report := checkProject(root)
		b, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Findings) == 0 || bytes.Contains(b, []byte("sensitive-value")) {
			t.Fatal("unsafe or missing findings")
		}
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	e := p.Env["dev"]
	e.Recipients = e.Recipients[:1]
	p.Env["dev"] = e
	if err := p.Save(root); err != nil {
		t.Fatal(err)
	}
	if len(checkProject(root).Findings) == 0 {
		t.Fatal("policy drift not reported")
	}
}

func TestSetEncryptsExactInputWithoutReadingPrivateKey(t *testing.T) {
	root, dev, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	t.Chdir(root)
	t.Setenv("ESEC_AGE_IDENTITY", "invalid-unused-identity")
	value := "quote ' \" dollar $ and\nsecond line\n"
	terminal := &syntheticRecoveryTerminal{answers: []string{value, value}}
	useRecoveryTerminal(t, terminal)
	if err := (&SetCmd{File: "dev", Key: "DATABASE_URL"}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(".env.dev")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("second line")) {
		t.Fatal("plaintext persisted")
	}
	t.Setenv("ESEC_AGE_IDENTITY", dev.String())
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := esec.ReadDocument(target, esec.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	vars, err := esec.EnvVars(plain, target.Format)
	if err != nil {
		t.Fatal(err)
	}
	if vars["DATABASE_URL"] != value {
		t.Fatal("value did not roundtrip")
	}
	// Prompt mismatch must leave the entire ciphertext untouched.
	terminal.answers = []string{"one", "two"}
	if err := (&SetCmd{File: "dev", Key: "EMPTY"}).Run(ctx); err == nil {
		t.Fatal("mismatch accepted")
	}
	after, err := os.ReadFile(".env.dev")
	if err != nil || !bytes.Equal(encrypted, after) {
		t.Fatal("failed update changed file")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Age.IdentityFiles) == 0 {
		t.Fatal("fixture invalid")
	}
}
