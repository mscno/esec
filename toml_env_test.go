package esec

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestTomlEnvMapping(t *testing.T) {
	got, err := EnvVars([]byte("_ESEC_PUBLIC_KEY='public'\nTOKEN='secret'\nPORT=8080\n[database]\nhost='localhost'\ntls=true\n"), FileFormatEtoml)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"TOKEN": "secret", "PORT": "8080", "DATABASE__HOST": "localhost", "DATABASE__TLS": "true"} {
		if got[k] != v {
			t.Fatalf("missing mapping for %s", k)
		}
	}
	if len(got) != 4 {
		t.Fatal("public key metadata was exported")
	}
	for _, bad := range []string{"DATABASE__HOST='a'\n[database]\nhost='b'", "LIST=['a']", "TOKEN=\"\\u0000\""} {
		if _, err := EnvVars([]byte(bad), FileFormatEtoml); err == nil {
			t.Fatal("accepted ambiguous or unsupported TOML")
		}
	}
}

func TestEnvironmentKeyNamesAreExact(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_PRIVATE_KEY", "")
	if err := os.Unsetenv("ESEC_PRIVATE_KEY"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"prod", "production"}, {"dev", "development"}, {"stage", "staging"}} {
		for _, names := range [][2]string{pair, {pair[1], pair[0]}} {
			t.Run(names[0]+"-is-not-"+names[1], func(t *testing.T) {
				pub, priv, err := GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				name := "ESEC_PRIVATE_KEY_" + strings.ToUpper(names[0])
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
				t.Setenv("ESEC_PRIVATE_KEY_"+strings.ToUpper(names[1]), priv)
				var encrypted strings.Builder
				if _, err := Encrypt(strings.NewReader("_ESEC_PUBLIC_KEY='"+pub+"'\nTOKEN='hello'\n"), &encrypted, FileFormatEtoml); err != nil {
					t.Fatal(err)
				}
				keydir := t.TempDir()
				var plain strings.Builder
				if _, err := Decrypt(strings.NewReader(encrypted.String()), &plain, names[0], FileFormatEtoml, keydir, ""); !errors.Is(err, ErrKeyNotFound) {
					t.Fatalf("used another environment's key: %v", err)
				}
				t.Setenv("ESEC_PRIVATE_KEY_"+strings.ToUpper(names[0]), priv)
				if _, err := Decrypt(strings.NewReader(encrypted.String()), &plain, names[0], FileFormatEtoml, keydir, ""); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(plain.String(), "hello") {
					t.Fatal("exact environment key failed")
				}
			})
		}
	}
}
