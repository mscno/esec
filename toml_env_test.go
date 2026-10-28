package esec

import (
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

func TestSuffixFileAndAliasKey(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_PRIVATE_KEY_PROD", priv)
	var encrypted strings.Builder
	if _, err := Encrypt(strings.NewReader("_ESEC_PUBLIC_KEY='"+pub+"'\nTOKEN='hello'\n"), &encrypted, FileFormatEtoml); err != nil {
		t.Fatal(err)
	}
	var plain strings.Builder
	if _, err := Decrypt(strings.NewReader(encrypted.String()), &plain, "production", FileFormatEtoml, "", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.String(), "hello") {
		t.Fatal("alias key failed")
	}
}
