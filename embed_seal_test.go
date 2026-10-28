package esec

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"

	"filippo.io/age"

	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
)

// A binary with its encrypted file and the file's seal embedded needs one
// secret, an age identity; the environment is the one whose seal it opens.
func TestDecryptFromFSWithEmbeddedSeal(t *testing.T) {
	t.Setenv("ESEC_KEYRING_DIR", t.TempDir())
	t.Setenv(EsecKeyringPath, "")
	t.Setenv("ESEC_CONFIG", "")
	t.Setenv(seal.EnvIdentityFile, "")
	t.Chdir(t.TempDir())

	fsys := fstest.MapFS{}
	deploy, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	pf := &projectfile.File{Project: "acme/api"}
	privs := map[string]string{}
	for env, reader := range map[string]age.Recipient{"prod": deploy.Recipient(), "dev": other.Recipient()} {
		pub, priv, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		pf.SetEnv(env, pub)
		privs[env] = priv
		var enc bytes.Buffer
		if _, err := Encrypt(strings.NewReader("ESEC_PUBLIC_KEY="+pub+"\nAPI="+env+"-secret\n"), &enc, FileFormatEnv); err != nil {
			t.Fatal(err)
		}
		fsys[".env."+env] = &fstest.MapFile{Data: enc.Bytes()}
		sealed, err := seal.Seal(seal.Payload{Project: "acme/api", Env: env, Private: priv}, reader)
		if err != nil {
			t.Fatal(err)
		}
		fsys[".esec/"+env+".age"] = &fstest.MapFile{Data: sealed}
	}
	toml, err := pf.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fsys["esec.toml"] = &fstest.MapFile{Data: toml}

	t.Setenv(seal.EnvIdentity, deploy.String())
	out, err := DecryptFromFS(fsys, DecryptFromEmbedConfig{Format: FileFormatEnv})
	if err != nil || !strings.Contains(string(out), "API=prod-secret") {
		t.Fatalf("decrypt with the deploy identity: %s %v", out, err)
	}
	// The identity opens prod only.
	if _, err := DecryptFromFS(fsys, DecryptFromEmbedConfig{Format: FileFormatEnv, EnvName: "dev"}); err == nil {
		t.Fatal("decrypted dev with prod's reader")
	}
	// Without esec.toml the file's public key binds the seal.
	delete(fsys, "esec.toml")
	if out, err := DecryptFromFS(fsys, DecryptFromEmbedConfig{Format: FileFormatEnv, EnvName: "prod"}); err != nil || !strings.Contains(string(out), "prod-secret") {
		t.Fatalf("decrypt without esec.toml: %s %v", out, err)
	}
	// A seal of another key is refused, though the identity opens it.
	fsys[".esec/prod.age"] = fsys[".esec/dev.age"]
	t.Setenv(seal.EnvIdentity, other.String())
	if _, err := DecryptFromFS(fsys, DecryptFromEmbedConfig{Format: FileFormatEnv, EnvName: "prod"}); err == nil {
		t.Fatal("opened a seal of another environment")
	}
	// A root key in ESEC_PRIVATE_KEY_PROD still works, needing no seal.
	t.Setenv(seal.EnvIdentity, "")
	delete(fsys, ".esec/prod.age")
	t.Setenv("ESEC_PRIVATE_KEY_PROD", privs["prod"])
	if out, err := DecryptFromFS(fsys, DecryptFromEmbedConfig{Format: FileFormatEnv}); err != nil || !strings.Contains(string(out), "prod-secret") {
		t.Fatalf("decrypt with the root key: %s %v", out, err)
	}
}
