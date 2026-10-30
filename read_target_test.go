package esec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
	"github.com/mscno/esec/pkg/secretstore"
)

func readFixture(t *testing.T, guard string) (string, string) {
	t.Helper()
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv("ESEC_SECRET_STORE", "file")
	t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
	t.Setenv("ESEC_KEYRING_PATH", "")
	t.Setenv("ESEC_AGE_IDENTITY", "")
	t.Setenv("ESEC_AGE_IDENTITY_FILE", "")
	root := t.TempDir()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pf := &projectfile.File{Project: "acme/store", Env: map[string]projectfile.Env{"production": {Key: pub, Guard: guard}}}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".env.production")
	if err := os.WriteFile(path, []byte("ESEC_PUBLIC_KEY="+pub+"\nTOKEN=hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptFileInPlace(path); err != nil {
		t.Fatal(err)
	}
	return root, priv
}

func TestReadResolutionUsesFileProjectAndExactName(t *testing.T) {
	root, priv := readFixture(t, "none")
	t.Setenv("ESEC_PRIVATE_KEY_PRODUCTION", priv)
	named, err := ResolveRead(root, "production", "")
	if err != nil {
		t.Fatal(err)
	}
	byfile, err := ResolveRead(t.TempDir(), filepath.Join(root, ".env.production"), "")
	if err != nil {
		t.Fatal(err)
	}
	if named.Environment != "production" || byfile.Project != named.Project || byfile.Digest != named.Digest {
		t.Fatalf("different targets: %+v %+v", named, byfile)
	}
	plain, err := ReadDocument(byfile, ReadOptions{})
	if err != nil || !strings.Contains(string(plain), "TOKEN=hello") {
		t.Fatalf("direct read: %s %v", plain, err)
	}
	if _, err := ResolveRead(root, "prod", ""); err == nil {
		t.Fatal("an alias selected production")
	}
}

func TestReadResolvesCustomProjectPattern(t *testing.T) {
	root, priv := readFixture(t, "none")
	pf, err := projectfile.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pf.Files = projectfile.Files{Format: "env", Name: "secrets/{env}.env"}
	if err := pf.Save(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "secrets", "production.env")
	if err := os.Rename(filepath.Join(root, ".env.production"), path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_PRIVATE_KEY_PRODUCTION", priv)
	target, err := ResolveRead(t.TempDir(), path, "")
	if err != nil || target.Environment != "production" {
		t.Fatalf("custom filename: %+v %v", target, err)
	}
	if _, err := ReadDocument(target, ReadOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestGuardPrecedesCachedAndExplicitKeys(t *testing.T) {
	root, priv := readFixture(t, "touch")
	t.Setenv("ESEC_PRIVATE_KEY_PRODUCTION", priv)
	t.Setenv("ESEC_VAULT_SOCK", filepath.Join(t.TempDir(), "missing.sock"))
	target, err := ResolveRead(root, "production", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.Route() != "daemon" {
		t.Fatal("guard selected a direct read")
	}
	if plain, err := ReadDocument(target, ReadOptions{PrivateKey: priv}); err == nil || len(plain) != 0 {
		t.Fatal("ordinary credentials bypassed the guard")
	}
	inspection := InspectRead(target, ReadOptions{})
	data, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), priv) || strings.Contains(string(data), "TOKEN") || strings.Contains(string(data), "content") {
		t.Fatal("inspection disclosed file content or a credential")
	}
	if len(inspection.Blockers) == 0 {
		t.Fatal("missing daemon was not explained")
	}
}

func TestSignedRecordCannotSilentlyDowngradeGuard(t *testing.T) {
	root, priv := readFixture(t, "none")
	pf, _ := projectfile.Load(root)
	pub := pf.Env["production"].Key
	id, _ := age.GenerateX25519Identity()
	data, err := seal.Seal(seal.Payload{Project: pf.Project, Env: "production", Guard: "touch", Private: priv}, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(root, "production", data); err != nil {
		t.Fatal(err)
	}
	rec := &seal.Record{Key: pub, Guard: "touch", Sealed: seal.Hash(data)}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec.Sign(pf.Project, "production", "test", sign)
	if err := (seal.Records{"production": rec}).Save(root); err != nil {
		t.Fatal(err)
	}
	target, err := ResolveRead(root, "production", "")
	if err != nil || target.Guard != "touch" {
		t.Fatalf("guard record ignored: %+v %v", target, err)
	}
	rec.Guard = "none"
	if err := (seal.Records{"production": rec}).Save(root); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveRead(root, "production", ""); err == nil {
		t.Fatal("changed signed metadata was accepted")
	}
}

func TestWorkloadIdentityOpensGuardedSealWithoutDaemon(t *testing.T) {
	root, priv := readFixture(t, "touch")
	pf, _ := projectfile.Load(root)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.Seal(seal.Payload{Project: pf.Project, Env: "production", Guard: "touch", Private: priv}, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(root, "production", sealed); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_AGE_IDENTITY", id.String())
	t.Setenv("ESEC_VAULT_SOCK", filepath.Join(t.TempDir(), "missing"))
	target, err := ResolveRead(root, "production", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := ReadDocument(target, ReadOptions{})
	if err != nil || !strings.Contains(string(data), "TOKEN=hello") {
		t.Fatalf("workload: %s %v", data, err)
	}
	other, _ := age.GenerateX25519Identity()
	t.Setenv("ESEC_AGE_IDENTITY", other.String())
	if _, err := ReadDocument(target, ReadOptions{}); err == nil {
		t.Fatal("an unauthorized identity opened the seal")
	}
}

func TestPublicKeyAddressedWorkloadCredentialStaysDirect(t *testing.T) {
	root, priv := readFixture(t, "touch")
	pf, _ := projectfile.Load(root)
	name := EsecPrivateKey + "_" + strings.ToUpper(pf.Env["production"].Key)
	t.Setenv(name, priv)
	t.Setenv("ESEC_VAULT_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	target, err := ResolveRead(root, "production", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.Route() != "workload_key" {
		t.Fatal("explicit workload key did not select direct access")
	}
	data, err := ReadDocument(target, ReadOptions{})
	if err != nil || !strings.Contains(string(data), "TOKEN=hello") {
		t.Fatalf("workload key: %s %v", data, err)
	}
	_, wrong, _ := GenerateKeypair()
	t.Setenv(name, wrong)
	if data, err := ReadDocument(target, ReadOptions{}); err == nil || len(data) != 0 {
		t.Fatal("wrong explicit workload key was accepted")
	}
}

func TestExplicitReadIgnoresUnrelatedCallerProject(t *testing.T) {
	root, priv := readFixture(t, "none")
	t.Setenv("ESEC_PRIVATE_KEY_PRODUCTION", priv)
	caller := t.TempDir()
	if err := os.WriteFile(filepath.Join(caller, "esec.toml"), []byte("invalid !!!"), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := ResolveRead(caller, filepath.Join(root, ".env.production"), "")
	if err != nil || target.Project != "acme/store" {
		t.Fatalf("caller contaminated explicit read: %+v %v", target, err)
	}
}

func TestPersonalIdentityReadsOrdinarySealLocally(t *testing.T) {
	root, priv := readFixture(t, "none")
	pf, _ := projectfile.Load(root)
	_, identityPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := seal.X25519Identity(identityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.Seal(seal.Payload{Project: pf.Project, Env: "production", Private: priv}, reader.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.Write(root, "production", sealed); err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("identity-private", identityPrivate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretstore.Home(), "identity.esec"), []byte("identity metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_VAULT_SOCK", filepath.Join(t.TempDir(), "missing.sock"))
	target, err := ResolveRead(root, "production", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESEC_SECRET_STORE", "invalid")
	inspection := InspectRead(target, ReadOptions{})
	if inspection.Route != "direct" {
		t.Fatalf("personal route: %+v", inspection)
	}
	t.Setenv("ESEC_SECRET_STORE", "file")
	plain, err := ReadDocument(target, ReadOptions{})
	if err != nil || !strings.Contains(string(plain), "TOKEN=hello") {
		t.Fatalf("personal read: %s %v", plain, err)
	}
}

func TestComponentReadUsesItsProjectLocalKeyring(t *testing.T) {
	root, priv := readFixture(t, "none")
	if err := os.WriteFile(filepath.Join(root, ".esec-keyring"), []byte("ESEC_PRIVATE_KEY_PRODUCTION="+priv+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "deploy")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, ".env.production")
	if err := os.Rename(filepath.Join(root, ".env.production"), file); err != nil {
		t.Fatal(err)
	}
	target, err := ResolveRead(t.TempDir(), file, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := ReadDocument(target, ReadOptions{})
	if err != nil || !strings.Contains(string(data), "TOKEN=hello") {
		t.Fatalf("project-local keyring: %s %v", data, err)
	}
}

func TestForwardedReadCarriesCiphertextAndNeverPrivateCredentials(t *testing.T) {
	t.Setenv("ESEC_VAULT_FORWARD", "/tmp/esec-forwarded.sock")
	path := filepath.Join(t.TempDir(), "prod.age")
	if err := os.WriteFile(path, []byte("sealed key"), 0600); err != nil {
		t.Fatal(err)
	}
	target := &ReadTarget{Project: "a/b", Environment: "prod", KeyEnvironment: "prod", Guard: "touch", Seal: path, Content: []byte("ciphertext")}
	req, sock, err := prepareReadRequest(target, ReadOptions{PrivateKey: "never-send-this-key"}, "read_document")
	if err != nil || sock != "/tmp/esec-forwarded.sock" || string(req.Content) != "ciphertext" || string(req.Seal) != "sealed key" {
		t.Fatalf("forwarded request: %+v %s %v", req, sock, err)
	}
	encoded, err := json.Marshal(req)
	if err != nil || strings.Contains(string(encoded), "never-send-this-key") {
		t.Fatal("private credential sent to a broker")
	}
	inspection := InspectRead(target, ReadOptions{})
	if inspection.Broker != "forwarded" || inspection.Hardware != "remote_not_verified" {
		t.Fatalf("forward inspection: %+v", inspection)
	}
	if _, _, err := prepareReadRequest(target, ReadOptions{}, "inspect_read"); err == nil {
		t.Fatal("remote inspection could request a guarded read")
	}
}
