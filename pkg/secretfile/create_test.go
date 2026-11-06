package secretfile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

func TestCreateRootStringPreservesStructuredValues(t *testing.T) {
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		format fileutils.FileFormat
		plain  string
	}{
		{fileutils.Ejson, `{"_ESEC_PUBLIC_KEY":"` + pub + `","_number":9007199254740993,"_public":{"enabled":true},"secret":"keep"}`},
		{fileutils.Etoml, "# keep comment\n_ESEC_PUBLIC_KEY='" + pub + "'\n_number=9007199254740993\nsecret='keep'\n[_public]\nenabled=true\n"},
	} {
		t.Run(string(test.format), func(t *testing.T) {
			var before bytes.Buffer
			if _, err := esec.Encrypt(strings.NewReader(test.plain), &before, esec.FileFormat(test.format)); err != nil {
				t.Fatal(err)
			}
			original, err := values(before.Bytes(), test.format)
			if err != nil {
				t.Fatal(err)
			}
			after, err := Set(before.Bytes(), test.format, "NEW_BLOB", "encoded", true)
			if err != nil {
				t.Fatal(err)
			}
			updated, err := values(after, test.format)
			if err != nil {
				t.Fatal(err)
			}
			if updated["secret"] != original["secret"] || !bytes.Contains(after, []byte("9007199254740993")) {
				t.Fatal("existing ciphertext or number changed")
			}
			if got, err := Check(after, test.format, "NEW_BLOB", priv); err != nil || got != "encoded" {
				t.Fatal("created value unreadable", err)
			}
			if _, err := Set(before.Bytes(), test.format, "_public", "overwrite", true); err == nil {
				t.Fatal("public metadata overwritten")
			}
			if _, err := Set(before.Bytes(), test.format, "MISSING.nested", "value", true); err == nil {
				t.Fatal("unsupported nested creation accepted")
			}
		})
	}
}
