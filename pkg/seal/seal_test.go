package seal

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/age"
)

func keypair(t *testing.T) (pub, priv string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	priv = hex.EncodeToString(raw)
	pub, err := PublicHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSealOpenRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	alice, _ := age.GenerateX25519Identity()
	bob, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	data, err := Seal(Payload{Project: "acme/store", Env: "prod", Guard: "touch", Private: priv}, alice.Recipient(), bob.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("not armored: %s", data[:40])
	}
	for _, id := range []age.Identity{alice, bob} {
		p, err := Open(data, "acme/store", "prod", pub, id)
		if err != nil || p.Private != priv || p.Guard != "touch" {
			t.Fatalf("open: %+v %v", p, err)
		}
	}
	if _, err := Open(data, "acme/store", "prod", pub, other); err == nil {
		t.Fatal("opened with an identity that is not a reader")
	}
	if _, err := Open(data, "acme/store", "dev", pub, alice); err == nil {
		t.Fatal("a prod key opened as dev")
	}
	if _, err := Open(data, "acme/other", "prod", pub, alice); err == nil {
		t.Fatal("a key opened for another project")
	}
	otherPub, _ := keypair(t)
	if _, err := Open(data, "acme/store", "prod", otherPub, alice); err == nil {
		t.Fatal("a key opened for files that use another public key")
	}
}

func TestKeyEncodings(t *testing.T) {
	pub, priv := keypair(t)
	id, err := X25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := X25519Recipient(pub)
	if err != nil || r != id.Recipient().String() {
		t.Fatalf("recipient %s != %s (%v)", r, id.Recipient(), err)
	}
	back, err := RecipientHex(r)
	if err != nil || back != pub {
		t.Fatalf("hex %s != %s (%v)", back, pub, err)
	}
	if _, err := ParseRecipient(r); err != nil {
		t.Fatal(err)
	}
	ids, err := ParseIdentities("# a comment\n\n"+id.String()+"\n", nil)
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities: %v %v", ids, err)
	}
	if pluginName("age1yubikey1qxyz") != "yubikey" || pluginName("age1pq1abc") != "" || pluginName(r) != "" {
		t.Fatal("plugin names")
	}
}

func TestEnvIdentities(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	t.Setenv(EnvIdentity, id.String())
	t.Setenv(EnvIdentityFile, "")
	ids, err := EnvIdentities()
	if err != nil || len(ids) != 1 {
		t.Fatalf("%v %v", ids, err)
	}
	t.Setenv(EnvIdentity, "")
	if ids, _ := EnvIdentities(); ids != nil {
		t.Fatal("identities from nothing")
	}
}
