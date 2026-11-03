package secretfile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

func TestDocumentDiscoveryUsesProjectFilenamePattern(t *testing.T) {
	root := t.TempDir()
	pub, _, _ := esec.GenerateKeypair()
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), []byte("project='acme/app'\n[files]\nname='secrets/app.{env}.etoml'\n[env.prod]\nkey='"+pub+"'\nguard='touch'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := esec.Encrypt(strings.NewReader("_ESEC_PUBLIC_KEY='"+pub+"'\nTOKEN='test'\n"), &out, esec.FileFormatEtoml); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secrets/app.prod.etoml"), out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := Scan(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("missing configured file: %v", err)
	}
	if files[0].Env != "prod" || files[0].Project != "acme/app" {
		t.Fatalf("wrong file identity: %+v", files[0])
	}
}

func TestDocumentValuesIncludeNestedAndArrays(t *testing.T) {
	values, err := DocumentValues([]byte(`{"_ESEC_PUBLIC_KEY":"public","_note":"metadata","db":{"password":"secret"},"tokens":["first",{"key":"second"}],"db.password":"literal","number":9007199254740993}`), fileutils.Ejson)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Value{
		"_note":           {Key: "_note", Value: "metadata"},
		"db.password":     {Key: "db.password", Value: "secret", Editable: true},
		`["db.password"]`: {Key: `["db.password"]`, Value: "literal"},
		"tokens[0]":       {Key: "tokens[0]", Value: "first"},
		"tokens[1].key":   {Key: "tokens[1].key", Value: "second"},
		"number":          {Key: "number", Value: "9007199254740993"},
	}
	if len(values) != len(want) {
		t.Fatalf("expected %d values, got %d", len(want), len(values))
	}
	for _, entry := range values {
		if entry != want[entry.Key] {
			t.Fatalf("incorrect entry %s", entry.Key)
		}
	}
}
