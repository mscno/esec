package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
)

func TestLocalDocumentReadEditAndConflicts(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	t.Chdir(root)
	path := filepath.Join(root, ".env.dev")
	original, err := os.ReadFile(path) //nolint:gosec // synthetic fixture under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	doc, err := (&SecretsShowCmd{File: path}).document(esec.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Decryption.Source != "local_age" || len(doc.Values) != 2 {
		t.Fatal("wrong document")
	}
	unchanged, err := os.ReadFile(path) //nolint:gosec // synthetic fixture under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, unchanged) {
		t.Fatal("read changed file")
	}
	value := "first\n# synthetic-edit-must-stay-encrypted\nlast '$VALUE'"
	revision, err := updateSecretDocument(path, secretUpdate{Revision: doc.Revision, Key: "DATABASE_URL", Value: &value})
	if err != nil {
		t.Fatal(err)
	}
	next, err := os.ReadFile(path) //nolint:gosec // synthetic fixture under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if revision == doc.Revision || bytes.Contains(next, []byte("synthetic-edit-must-stay-encrypted")) {
		t.Fatal("edit not encrypted")
	}
	opened, err := (&SecretsShowCmd{File: path}).document(esec.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Values[0].Value != value {
		t.Fatal("multiline value not preserved")
	}
	if _, err := updateSecretDocument(path, secretUpdate{Revision: doc.Revision, Key: "DATABASE_URL", Value: &value}); err == nil {
		t.Fatal("stale revision saved")
	}
	if _, err := updateSecretDocument(path, secretUpdate{Revision: revision, Key: "ESEC_PUBLIC_KEY", Value: &value, Create: true}); err == nil {
		t.Fatal("public key overwritten")
	}
	after, err := os.ReadFile(path) //nolint:gosec // synthetic fixture under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(next, after) {
		t.Fatal("rejected edit changed file")
	}
}
func TestLocalOnlyNeverContactsLegacyBroker(t *testing.T) {
	root, _, _, ctx := standaloneFixture(t)
	initStandalone(t, root, ctx)
	t.Chdir(root)
	pub, _, err := esec.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pf := &projectfile.File{Project: "test/legacy", Env: map[string]projectfile.Env{"production": {Key: pub, Guard: "touch"}}}
	data, err := pf.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "esec.toml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.production"), []byte("ESEC_PUBLIC_KEY="+pub+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = (&SecretsShowCmd{File: filepath.Join(root, ".env.production")}).document(esec.ReadOptions{})
	if err == nil || !strings.Contains(err.Error(), "legacy_guard_requires_migration") {
		t.Fatalf("unexpected failure: %v", err)
	}
}
func TestGUIProtocolKeepsPINOutOfOutputAndRejectsMismatchedReply(t *testing.T) {
	var output bytes.Buffer
	protocol := newGUIProtocol(strings.NewReader("{\"id\":1,\"value\":\"synthetic-pin\"}\n"), &output)
	value, err := protocol.ui().RequestValue("yubikey", "PIN", true)
	if err != nil || value != "synthetic-pin" {
		t.Fatal("PIN reply failed")
	}
	if strings.Contains(output.String(), "synthetic-pin") || !strings.Contains(output.String(), `"secret":true`) {
		t.Fatal("PIN leaked or request was not masked")
	}
	protocol = newGUIProtocol(strings.NewReader("{\"id\":9,\"value\":\"must-not-return\"}\n"), &output)
	value, err = protocol.ui().RequestValue("yubikey", "PIN", true)
	if err == nil || value != "" {
		t.Fatal("mismatched response accepted")
	}
}
