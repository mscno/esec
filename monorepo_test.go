package esec

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec/pkg/projectfile"
)

func TestKeySuffixes(t *testing.T) {
	cases := map[string][]string{
		"":                    {""},
		"dev":                 {"DEV"},
		"production":          {"PRODUCTION"},
		"registry.production": {"REGISTRY_PRODUCTION", "PRODUCTION"},
		"a.b.c":               {"A_B_C", "C"},
		"prod.test":           {"PROD_TEST", "TEST"},
	}
	for in, want := range cases {
		got := KeySuffixes(in)
		if len(got) != len(want) {
			t.Fatalf("KeySuffixes(%q) = %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("KeySuffixes(%q) = %v, want %v", in, got, want)
			}
		}
	}
}

func TestParseEnvSuffix(t *testing.T) {
	cases := map[string]string{
		".env":                          "",
		".ejson":                        "",
		".env.dev":                      "dev",
		".ejson.prod":                   "prod",
		".env.registry.production":      "registry.production",
		"services/api/.env.api.staging": "api.staging",
		".eyaml.payments.eu.prod":       "payments.eu.prod",
	}
	for in, want := range cases {
		if got := parseEnvSuffix(in); got != want {
			t.Errorf("parseEnvSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

// encryptWithKeypair encrypts a small ejson doc with a fresh keypair and
// returns the ciphertext, the pubkey, and the privkey hex.
func encryptWithKeypair(t *testing.T) (data []byte, pub, priv string) {
	t.Helper()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plain := `{"_ESEC_PUBLIC_KEY": "` + pub + `", "SECRET": "s3cret"}`
	var out bytes.Buffer
	if _, err := Encrypt(strings.NewReader(plain), &out, FileFormatEjson); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), pub, priv
}

func TestPubkeyKeyedLookup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	t.Setenv(EsecKeyringDir, t.TempDir())

	t.Run("resolves by file public key", func(t *testing.T) {
		data, pub, priv := encryptWithKeypair(t)
		repo := t.TempDir()
		// Keyring holds ONLY the pubkey-keyed entry.
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			fmt.Sprintf("ESEC_PRIVATE_KEY_%s=%s\n", strings.ToUpper(pub), priv))

		key, err := findPrivateKeyForData(repo, "production", "", data, FileFormatEjson, logger)
		if err != nil {
			t.Fatalf("findPrivateKeyForData: %v", err)
		}
		want, _ := hex.DecodeString(priv)
		if key != [32]byte(want) {
			t.Fatal("wrong key resolved")
		}
		// And it must actually decrypt.
		var out bytes.Buffer
		if _, err := Decrypt(bytes.NewReader(data), &out, "production", FileFormatEjson, repo, ""); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !strings.Contains(out.String(), `"SECRET": "s3cret"`) {
			t.Fatalf("decrypt failed: %s", out.String())
		}
	})

	t.Run("pubkey entry with mismatched private key errors loudly", func(t *testing.T) {
		data, pub, _ := encryptWithKeypair(t)
		_, _, otherPriv := encryptWithKeypair(t)
		repo := t.TempDir()
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			fmt.Sprintf("ESEC_PRIVATE_KEY_%s=%s\n", strings.ToUpper(pub), otherPriv))

		_, err := findPrivateKeyForData(repo, "production", "", data, FileFormatEjson, logger)
		if err == nil || !strings.Contains(err.Error(), "does not match that public key") {
			t.Fatalf("expected pubkey mismatch error, got %v", err)
		}
	})

	t.Run("lowercase hex pubkey entry accepted", func(t *testing.T) {
		data, pub, priv := encryptWithKeypair(t)
		repo := t.TempDir()
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			fmt.Sprintf("ESEC_PRIVATE_KEY_%s=%s\n", pub, priv))

		if _, err := findPrivateKeyForData(repo, "production", "", data, FileFormatEjson, logger); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("name beats pubkey when both present", func(t *testing.T) {
		data, pub, priv := encryptWithKeypair(t)
		nameKey := "1111111111111111111111111111111111111111111111111111111111111111"
		repo := t.TempDir()
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			fmt.Sprintf("ESEC_PRIVATE_KEY_PRODUCTION=%s\nESEC_PRIVATE_KEY_%s=%s\n", nameKey, strings.ToUpper(pub), priv))

		key, err := findPrivateKeyForData(repo, "production", "", data, FileFormatEjson, logger)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(nameKey)
		if key != [32]byte(want) {
			t.Fatal("name-based entry should win over pubkey entry")
		}
	})

	t.Run("pubkey lookup via environment variable", func(t *testing.T) {
		data, pub, priv := encryptWithKeypair(t)
		t.Setenv(fmt.Sprintf("ESEC_PRIVATE_KEY_%s", strings.ToUpper(pub)), priv)
		repo := t.TempDir() // no keyring anywhere

		if _, err := findPrivateKeyForData(repo, "production", "", data, FileFormatEjson, logger); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDottedEnvLookupChain(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	t.Setenv(EsecKeyringDir, t.TempDir())
	full := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	last := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	t.Run("full suffix wins over last segment", func(t *testing.T) {
		repo := t.TempDir()
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			"ESEC_PRIVATE_KEY_REGISTRY_PRODUCTION="+full+"\nESEC_PRIVATE_KEY_PRODUCTION="+last+"\n")
		key, err := findPrivateKeyForData(repo, "registry.production", "", nil, "", logger)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(full)
		if key != [32]byte(want) {
			t.Fatal("full suffix should win")
		}
	})

	t.Run("last segment fallback", func(t *testing.T) {
		repo := t.TempDir()
		writeKeyring(t, filepath.Join(repo, DefaultKeyringFilename),
			"ESEC_PRIVATE_KEY_PRODUCTION="+last+"\n")
		key, err := findPrivateKeyForData(repo, "registry.production", "", nil, "", logger)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(last)
		if key != [32]byte(want) {
			t.Fatal("last-segment fallback failed")
		}
	})

	t.Run("env vars follow the same chain", func(t *testing.T) {
		t.Setenv("ESEC_PRIVATE_KEY_REGISTRY_STAGING", full)
		repo := t.TempDir()
		key, err := findPrivateKeyForData(repo, "registry.staging", "", nil, "", logger)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(full)
		if key != [32]byte(want) {
			t.Fatal("env var chain failed")
		}
	})
}

func TestExtractPublicKey(t *testing.T) {
	data, pub, _ := encryptWithKeypair(t)
	extracted, err := ExtractPublicKey(data, FileFormatEjson)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(pub)
	if extracted != [32]byte(want) {
		t.Fatal("extracted wrong public key")
	}
	if _, err := ExtractPublicKey([]byte("not json"), FileFormatEjson); err == nil {
		t.Fatal("expected error for garbage")
	}
}

func TestFindProjectFileStopsAtGitRoot(t *testing.T) {
	// A parent dir with a project file that must NOT leak into nested repos.
	parent := t.TempDir()
	if err := projectfile.WriteProjectFile(parent, "org/parent"); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(parent, "myrepo")
	sub := filepath.Join(repo, "services", "api")
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0750); err != nil {
		t.Fatal(err)
	}

	if _, _, err := projectfile.FindProjectFile(sub); err == nil {
		t.Fatal("expected no project found: walk must stop at git root")
	}

	// A nested .esec-project inside the repo still wins.
	if err := projectfile.WriteProjectFile(filepath.Join(repo, "services"), "org/repo/services"); err != nil {
		t.Fatal(err)
	}
	project, _, err := projectfile.FindProjectFile(sub)
	if err != nil {
		t.Fatal(err)
	}
	if project != "org/repo/services" {
		t.Fatalf("unexpected project: %s", project)
	}

	// And a project file at the git root itself is found.
	if err := projectfile.WriteProjectFile(repo, "org/repo"); err != nil {
		t.Fatal(err)
	}
	project, _, err = projectfile.FindProjectFile(repo)
	if err != nil || project != "org/repo" {
		t.Fatalf("git-root project file should be found: %s %v", project, err)
	}
}

func TestValidateOrgRepoExtended(t *testing.T) {
	valid := []string{"org/repo", "org/repo/services/registry", "org/repo/a/b/c"}
	for _, v := range valid {
		if err := projectfile.ValidateOrgRepo(v); err != nil {
			t.Errorf("expected %q valid, got %v", v, err)
		}
	}
	invalid := []string{"org", "org/", "org//x", "org/repo/../x", "org/repo/./x"}
	for _, v := range invalid {
		if err := projectfile.ValidateOrgRepo(v); err == nil {
			t.Errorf("expected %q invalid", v)
		}
	}
	if got := projectfile.KeyringName("org/repo/services/registry"); got != "org_repo_services_registry.keyring" {
		t.Errorf("unexpected keyring name %q", got)
	}
}
