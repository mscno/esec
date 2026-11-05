package commands

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
)

func TestInitPlaintextWithOldPublicHeaders(t *testing.T) { //nolint:gocyclo // consent, round-trip, and missing-file behavior in one scenario
	for _, header := range []string{"ESEC_PUBLIC_KEY=%s\n", "export ESEC_PUBLIC_KEY=\"%s\"\n", "_ESEC_PUBLIC_KEY=%s\n", "ESEC_PUBLIC_KEY=%[1]s\n_ESEC_PUBLIC_KEY=%[1]s\n"} {
		t.Run(header, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			oldPublic, _, err := esec.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			original := []byte(fmt.Sprintf(header, oldPublic) + "TOKEN=\"first\n# synthetic-continuation\nlast\"\nDOLLAR='literal$dollar'\nEMPTY=\n")
			path := filepath.Join(root, ".env.dev")
			writeFixture(t, path, original)
			writeFixture(t, filepath.Join(root, ".env.test"), []byte("TEST_VALUE=synthetic-test\n"))
			writeFixture(t, filepath.Join(root, ".env.example"), []byte("NEVER_COPY=synthetic-example\n"))
			cmd := InitCmd{Project: "test/app", Env: "dev,test,staging", Dir: root, Yes: true}
			if err := cmd.Run(ctx); err == nil || !strings.Contains(err.Error(), "--encrypt-existing") {
				t.Fatal("missing plaintext consent error", err)
			}
			assertUnchanged(t, path, original)
			assertAbsent(t, filepath.Join(root, "esec.toml"))
			assertAbsent(t, filepath.Join(root, ".env.staging"))
			cmd.EncryptExisting = true
			if err := cmd.Run(ctx); err != nil {
				t.Fatal(err)
			}
			target, err := esec.ResolveRead(root, "dev", "")
			if err != nil {
				t.Fatal(err)
			}
			if target.PublicKey == oldPublic || bytes.Contains(target.Content, []byte("synthetic-continuation")) || bytes.Contains(target.Content, []byte("literal$dollar")) {
				t.Fatal("old header or plaintext survived encryption")
			}
			plain, err := esec.ReadDocument(target, esec.ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			want, err := godotenv.Unmarshal(string(original))
			if err != nil {
				t.Fatal(err)
			}
			got, err := godotenv.Unmarshal(string(plain))
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"TOKEN", "DOLLAR", "EMPTY"} {
				if value, ok := got[key]; !ok || value != want[key] {
					t.Fatalf("value changed for %s", key)
				}
			}
			if got["_ESEC_PUBLIC_KEY"] != "" || strings.Count(string(plain), "ESEC_PUBLIC_KEY") != 1 {
				t.Fatal("duplicate public-key header")
			}
			staging, err := esec.ResolveRead(root, "staging", "")
			if err != nil || bytes.Contains(staging.Content, []byte("NEVER_COPY")) || bytes.Count(bytes.TrimSpace(staging.Content), []byte("\n")) != 0 {
				t.Fatal("missing file must get only a public key", err)
			}
		})
	}
}

func TestInitRefusesEncryptedAndMixedLegacyFiles(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			_, encrypted := legacyAdoptionFixture(t, root)
			if mixed {
				encrypted = append(encrypted, []byte("PLAIN=synthetic\n")...)
				writeFixture(t, filepath.Join(root, ".env.dev"), encrypted)
			}
			err := (&InitCmd{Project: "test/app", Env: "dev", Dir: root, Yes: true, EncryptExisting: true}).Run(ctx)
			if err == nil || !strings.Contains(err.Error(), "esec adopt") || !strings.Contains(err.Error(), "--project") {
				t.Fatal("expected actionable adoption error", err)
			}
			assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
			assertAbsent(t, filepath.Join(root, "esec.toml"))
		})
	}
}

func TestAdoptBootstrapsProjectWithLegacyKey(t *testing.T) {
	for _, source := range []string{"local-keyring", "global-keyring", "explicit-keyring", "environment", "project-only"} {
		t.Run(source, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			t.Chdir(root)
			private, encrypted := legacyAdoptionFixture(t, root)
			t.Setenv("ESEC_KEYRING_PATH", "")
			// The fixture clears these variables; keyring lookup needs them absent.
			if err := os.Unsetenv("ESEC_PRIVATE_KEY_DEV"); err != nil {
				t.Fatal(err)
			}
			if err := os.Unsetenv("ESEC_PRIVATE_KEY"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
			keyring := []byte("ESEC_PRIVATE_KEY_DEV=" + private + "\n")
			switch source {
			case "local-keyring":
				writeFixture(t, filepath.Join(root, ".esec-keyring"), keyring)
			case "global-keyring":
				writeFixture(t, filepath.Join(esec.GlobalKeyringDir(), projectfile.KeyringName("test/app")), keyring)
			case "explicit-keyring":
				path := filepath.Join(t.TempDir(), "recovered.keyring")
				writeFixture(t, path, keyring)
				t.Setenv("ESEC_KEYRING_PATH", path)
			default:
				t.Setenv("ESEC_PRIVATE_KEY_DEV", private)
			}
			if source == "project-only" {
				writeFixture(t, filepath.Join(root, "esec.toml"), []byte("project = 'test/app'\n"))
			} else {
				if err := (&AdoptCmd{File: "dev"}).Run(ctx); err == nil || !strings.Contains(err.Error(), "--project") {
					t.Fatal("missing project advice", err)
				}
				assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
			}
			if err := (&AdoptCmd{File: "dev", Project: "test/app"}).Run(ctx); err != nil {
				t.Fatal(err)
			}
			target, err := esec.ResolveRead(root, "dev", "")
			if err != nil || !target.Standalone || target.Project != "test/app" || target.PolicyStatus != "current" {
				t.Fatal("adoption metadata incomplete", err)
			}
			plain, err := esec.ReadDocument(target, esec.ReadOptions{})
			if err != nil || !bytes.Contains(plain, []byte("TOKEN=synthetic-adoption")) {
				t.Fatal("adoption lost original value", err)
			}
		})
	}
}

func TestFailedAdoptDoesNotPublishProject(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	t.Chdir(root)
	_, encrypted := legacyAdoptionFixture(t, root)
	if err := (&AdoptCmd{File: "dev", Project: "test/app"}).Run(ctx); err == nil {
		t.Fatal("adopted without original key")
	}
	assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
	assertAbsent(t, filepath.Join(root, "esec.toml"))
	assertAbsent(t, filepath.Join(root, ".esec", "keys"))
}

func TestBootstrapRefusesOrphanedAccess(t *testing.T) {
	for _, artifact := range []string{"dev.age", "seals.toml", "keys/dev/old.age"} {
		t.Run(artifact, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			t.Chdir(root)
			private, encrypted := legacyAdoptionFixture(t, root)
			t.Setenv("ESEC_PRIVATE_KEY_DEV", private)
			path := filepath.Join(root, ".esec", artifact)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, []byte("synthetic-access-data"))
			if err := (&AdoptCmd{File: "dev", Project: "test/app"}).Run(ctx); err == nil {
				t.Fatal("adopt guessed missing access policy")
			}
			if err := (&InitCmd{Project: "test/app", Env: "dev", Dir: root, Yes: true, EncryptExisting: true}).Run(ctx); err == nil {
				t.Fatal("init guessed missing access policy")
			}
			assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
			assertAbsent(t, filepath.Join(root, "esec.toml"))
		})
	}
}

func TestAdoptRejectsProjectMismatchAndInvalidProject(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	t.Chdir(root)
	_, encrypted := legacyAdoptionFixture(t, root)
	if err := (&AdoptCmd{File: "dev", Project: "../app"}).Run(ctx); err == nil {
		t.Fatal("accepted invalid project")
	}
	writeFixture(t, filepath.Join(root, "esec.toml"), []byte("project = 'test/original'\n"))
	if err := (&AdoptCmd{File: "dev", Project: "test/different"}).Run(ctx); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatal("accepted project mismatch", err)
	}
	assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
}

func TestAdoptRefusesConcurrentMetadataCreation(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	t.Chdir(root)
	private, encrypted := legacyAdoptionFixture(t, root)
	target, err := esec.ResolveRead(root, "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := adoptionProject(target, "test/app")
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("project = 'test/concurrent'\n")
	writeFixture(t, filepath.Join(root, "esec.toml"), marker)
	if err := rotateStandaloneProject(ctx, target, nil, esec.ReadOptions{PrivateKey: private}, bootstrap); err == nil {
		t.Fatal("overwrote concurrent project")
	}
	assertUnchanged(t, filepath.Join(root, "esec.toml"), marker)
	assertUnchanged(t, filepath.Join(root, ".env.dev"), encrypted)
}

func TestAdoptBootstrapNestedFilesAndRepositoryBoundaries(t *testing.T) {
	for _, scenario := range []string{"nested", "nested-repo", "outside", "orphaned-parent"} {
		t.Run(scenario, func(t *testing.T) {
			root, _, _, ctx := standaloneFixture(t)
			nested := filepath.Join(root, "secrets")
			if err := os.Mkdir(nested, 0700); err != nil {
				t.Fatal(err)
			}
			private, encrypted := legacyAdoptionFixture(t, nested)
			t.Setenv("ESEC_PRIVATE_KEY_DEV", private)
			t.Chdir(root)
			switch scenario {
			case "nested-repo":
				writeFixture(t, filepath.Join(nested, ".git"), []byte("gitdir: synthetic\n"))
			case "outside":
				t.Chdir(t.TempDir())
			case "orphaned-parent":
				if err := os.Mkdir(filepath.Join(root, ".esec"), 0700); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(root, ".esec", "dev.age"), []byte("synthetic-seal"))
				t.Chdir(nested)
			}
			path := filepath.Join(nested, ".env.dev")
			err := (&AdoptCmd{File: path, Project: "test/app"}).Run(ctx)
			if scenario != "nested" {
				if err == nil {
					t.Fatal("adoption crossed an access boundary")
				}
				assertUnchanged(t, path, encrypted)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			target, err := esec.ResolveRead(root, "dev", "")
			if err != nil || !target.Standalone || target.Environment != "dev" {
				t.Fatal("nested filename was not recorded correctly", err)
			}
		})
	}
}

func legacyAdoptionFixture(t *testing.T, root string) (string, []byte) {
	t.Helper()
	public, private, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encryptBytes([]byte("ESEC_PUBLIC_KEY="+public+"\nTOKEN=synthetic-adoption\n"), esec.FileFormatEnv)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, ".env.dev"), encrypted)
	return private, encrypted
}

func writeFixture(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path) //nolint:gosec // synthetic file created under t.TempDir
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("file changed unexpectedly", err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("unexpected file after refusal", err)
	}
}
