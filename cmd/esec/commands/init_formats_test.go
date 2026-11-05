package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/secretfile"
)

func TestInitSelectsFormatAndReusesProjectPattern(t *testing.T) {
	for _, format := range []string{"env", "etoml", "ejson", "eyaml", "eyml"} {
		t.Run(format, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			cmd := InitCmd{Project: "test/formats", Env: "dev", Format: format, Dir: root, Yes: true}
			if err := cmd.Run(ctx); err != nil {
				t.Fatal(err)
			}
			pf, err := projectfile.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			if pf.FilesFormat() != format {
				t.Fatal("wrong persisted format")
			}
			for _, env := range []string{"dev", "test"} {
				if env == "test" {
					if err := (&InitCmd{Env: env, Dir: root, Yes: true}).Run(ctx); err != nil {
						t.Fatal(err)
					}
				}
				target, err := esec.ResolveRead(root, env, "")
				if err != nil {
					t.Fatal(err)
				}
				plain, err := esec.ReadDocument(target, esec.ReadOptions{})
				if err != nil {
					t.Fatal(err)
				}
				values, err := secretfile.DocumentValues(plain, fileutils.FileFormat(target.Format))
				if err != nil {
					t.Fatal(err)
				}
				if format == "env" && len(values) == 1 && values[0].Key == "ESEC_PUBLIC_KEY" {
					values = nil
				}
				if len(values) != 0 {
					t.Fatal("new file must contain only its public key")
				}
			}
			before, _ := os.ReadFile(filepath.Join(root, "esec.toml")) //nolint:gosec // test fixture
			other := "ejson"
			if format == other {
				other = "env"
			}
			if err := (&InitCmd{Env: "staging", Format: other, Dir: root, Yes: true}).Run(ctx); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatal("expected format conflict", err)
			}
			after, _ := os.ReadFile(filepath.Join(root, "esec.toml")) //nolint:gosec // test fixture
			if !bytes.Equal(before, after) {
				t.Fatal("conflicting format changed project")
			}
		})
	}
}

func TestInitEncryptsExistingStructuredValuesWithConsent(t *testing.T) {
	for format, body := range map[string]string{
		"etoml": "_ESEC_PUBLIC_KEY='old'\ncount=9007199254740993\n[database]\npassword='synthetic-secret'\nlabels=['one','two']\n",
		"ejson": `{"_ESEC_PUBLIC_KEY":"old","count":9007199254740993,"database":{"password":"synthetic-secret","labels":["one","two"]}}`,
		"eyaml": "_ESEC_PUBLIC_KEY: old\ncount: 9007199254740993\ndatabase:\n  password: synthetic-secret\n  labels: [one, two]\n",
	} {
		t.Run(format, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			path := filepath.Join(root, "."+format+".dev")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := InitCmd{Project: "test/formats", Env: "dev", Format: format, Dir: root, Yes: true}
			if err := cmd.Run(ctx); err == nil || !strings.Contains(err.Error(), "--encrypt-existing") {
				t.Fatal("expected consent error", err)
			}
			unchanged, _ := os.ReadFile(path) //nolint:gosec // test fixture
			if string(unchanged) != body {
				t.Fatal("plaintext changed without consent")
			}
			cmd.EncryptExisting = true
			if err := cmd.Run(ctx); err != nil {
				t.Fatal(err)
			}
			target, err := esec.ResolveRead(root, "dev", "")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(target.Content, []byte("synthetic-secret")) {
				t.Fatal("secret left on disk")
			}
			plain, err := esec.ReadDocument(target, esec.ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"synthetic-secret", "9007199254740993", "one", "two"} {
				if !bytes.Contains(plain, []byte(want)) {
					t.Fatal("lost structured value")
				}
			}
		})
	}
}

func TestInitUsesCustomStructuredFilename(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	pf := &projectfile.File{Project: "test/formats", Files: projectfile.Files{Name: "secrets/{env}.etoml"}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if err := (&InitCmd{Env: "dev", Format: "etoml", Dir: root, Yes: true}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "secrets/dev.etoml")); err != nil {
		t.Fatal(err)
	}
}

func TestInitRefusesInvalidStructuredInputWithoutChangingFiles(t *testing.T) {
	for _, tc := range []struct{ format, body string }{
		{"ejson", `{"password":"must-not-echo", BROKEN}`},
		{"ejson", `{"password":"must-not-echo"} {}`},
		{"ejson", `{"password":"ESEC[broken]"}`},
		{"etoml", "password='must-not-echo'\nbroken=[\n"},
		{"etoml", "password='ESEC[broken]'\n"},
		{"eyaml", "password: must-not-echo\n---\nother: 1\n"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			path := filepath.Join(root, "."+tc.format+".dev")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			err := (&InitCmd{Project: "test/formats", Env: "dev", Format: tc.format, Dir: root, Yes: true, EncryptExisting: true}).Run(ctx)
			if err == nil || strings.Contains(err.Error(), "must-not-echo") {
				t.Fatal("expected safe refusal")
			}
			unchanged, err := os.ReadFile(path) //nolint:gosec // test fixture
			if err != nil || string(unchanged) != tc.body {
				t.Fatal("existing data changed")
			}
			if _, err := os.Stat(filepath.Join(root, "esec.toml")); !os.IsNotExist(err) {
				t.Fatal("published failed project")
			}
		})
	}
}
