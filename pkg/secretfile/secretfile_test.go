package secretfile_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"

	"github.com/mscno/esec/pkg/secretfile"
)

func encrypted(t *testing.T, f fileutils.FileFormat, plain string) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader(plain), &out, esec.FileFormat(f)); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestPlainCountsConcurrentJSONScalars(t *testing.T) {
	data := []byte(`{"items":[` + strings.Repeat(`"value",`, 255) + `"value"]}`)
	plain, err := secretfile.Plain(data, fileutils.Ejson)
	if err != nil || len(plain) != 1 || plain[0] != "256 value(s)" {
		t.Fatalf("plaintext array values were missed: %v %v", plain, err)
	}
}

// Setting a value in each format: only that value changes, it is
// encrypted, and it decrypts to the new value.
func TestSetEachFormat(t *testing.T) {
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		f     fileutils.FileFormat
		plain string
		path  string
	}{
		{fileutils.Env, "ESEC_PUBLIC_KEY=" + pub + "\n# the database\nDATABASE_URL=postgres://old\nAPI_KEY=k1\n", "DATABASE_URL"},
		{fileutils.Ejson, `{
  "_ESEC_PUBLIC_KEY": "` + pub + `",
  "db": {"password": "old", "user": "app"},
  "api_key": "k1"
}
`, "db.password"},
		{fileutils.Etoml, "_ESEC_PUBLIC_KEY = \"" + pub + "\"\napi_key = \"k1\"\n\n[db]\npassword = \"old\"\nuser = \"app\"\n", "db.password"},
		{fileutils.Eyaml, "_ESEC_PUBLIC_KEY: " + pub + "\ndb:\n    password: old\n    user: app\napi_key: k1\n", "db.password"},
	}
	for _, c := range cases {
		t.Run(string(c.f), func(t *testing.T) {
			data := encrypted(t, c.f, c.plain)
			before, err := secretfile.Keys(data, c.f)
			if err != nil {
				t.Fatal(err)
			}
			newValue := `p@ss "word" with spaces #and $dollar \ back`
			out, err := secretfile.Set(data, c.f, c.path, newValue, false)
			if err != nil {
				t.Fatalf("set: %v", err)
			}
			if strings.Contains(string(out), "p@ss") {
				t.Fatal("the new value is in the clear")
			}
			got, err := secretfile.Check(out, c.f, c.path, priv)
			if err != nil || got != newValue {
				t.Fatalf("check: %q %v", got, err)
			}
			after, _ := secretfile.Keys(out, c.f)
			if strings.Join(before, ",") != strings.Join(after, ",") {
				t.Fatalf("keys changed: %v -> %v", before, after)
			}
			if plain, _ := secretfile.Plain(out, c.f); len(plain) != 0 {
				t.Fatalf("left in the clear: %v", plain)
			}
			// Every other ciphertext is kept, so the diff is one value
			// (YAML is written out again by esec, in its layout).
			if c.f != fileutils.Eyaml {
				changed := 0
				a, b := strings.Split(string(data), "\n"), strings.Split(string(out), "\n")
				if len(a) != len(b) {
					t.Fatalf("lines: %d -> %d", len(a), len(b))
				}
				for i := range a {
					if a[i] != b[i] {
						changed++
					}
				}
				if changed != 1 {
					t.Fatalf("%d lines changed", changed)
				}
			}
			if _, err := secretfile.Set(data, c.f, "nope.missing", "x", false); !errors.Is(err, secretfile.ErrNotFound) {
				t.Fatalf("missing key: %v", err)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	pub, _, _ := esec.GenerateKeypair()
	data := encrypted(t, fileutils.Ejson, `{"_ESEC_PUBLIC_KEY": "`+pub+`", "_note": "x", "a": "b"}`)
	if _, err := secretfile.Set(data, fileutils.Ejson, "_note", "y", false); err == nil {
		t.Fatal("set a key esec does not encrypt")
	}
	if _, err := secretfile.Set(data, fileutils.Ejson, "_ESEC_PUBLIC_KEY", "y", false); err == nil {
		t.Fatal("set the public key")
	}
	if _, err := secretfile.Set(data, fileutils.Ejson, "a", "ESEC[1:x]", false); err == nil {
		t.Fatal("set an encrypted-looking value")
	}
	env := encrypted(t, fileutils.Env, "ESEC_PUBLIC_KEY="+pub+"\nA=1\n")
	out, err := secretfile.Set(env, fileutils.Env, "B", "2", true)
	if err != nil {
		t.Fatal(err)
	}
	if keys, _ := secretfile.Keys(out, fileutils.Env); strings.Join(keys, ",") != "A,B" {
		t.Fatalf("create: %v", keys)
	}
}

// Scan finds files, their environments and projects, and values in the
// clear.
func TestScanAndPlain(t *testing.T) {
	pub, _, _ := esec.GenerateKeypair()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), []byte("project = \"acme/api\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.prod"), encrypted(t, fileutils.Env, "ESEC_PUBLIC_KEY="+pub+"\nDB=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A secret someone pasted in after encrypting.
	leaky := string(encrypted(t, fileutils.Env, "ESEC_PUBLIC_KEY="+pub+"\nDB=x\n")) + "TOKEN=plaintext\n"
	if err := os.WriteFile(filepath.Join(root, ".env.dev"), []byte(leaky), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := secretfile.Scan(root)
	if err != nil || len(files) != 2 {
		t.Fatalf("scan: %v %+v", err, files)
	}
	for _, f := range files {
		if f.Project != "acme/api" || f.PublicKey != pub {
			t.Fatalf("file: %+v", f)
		}
		switch f.Env {
		case "prod":
			if len(f.Plain) != 0 || !f.Has("DB") {
				t.Fatalf("prod: %+v", f)
			}
		case "dev":
			if strings.Join(f.Plain, ",") != "TOKEN" {
				t.Fatalf("dev plain: %+v", f.Plain)
			}
		default:
			t.Fatalf("env %q", f.Env)
		}
	}
}
