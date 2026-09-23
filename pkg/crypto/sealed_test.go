package crypto

import (
	"bytes"
	"testing"
)

func TestSealAnonymousRoundTrip(t *testing.T) {
	var kp Keypair
	if err := kp.Generate(); err != nil {
		t.Fatal(err)
	}

	msg := []byte("restore me from a mnemonic")
	sealed, err := SealAnonymous(msg, &kp.Public)
	if err != nil {
		t.Fatalf("SealAnonymous: %v", err)
	}
	if bytes.Contains(sealed, msg) {
		t.Fatal("sealed output contains plaintext")
	}

	opened, err := OpenAnonymous(sealed, &kp.Public, &kp.Private)
	if err != nil {
		t.Fatalf("OpenAnonymous: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("round trip mismatch: %q", opened)
	}
}

func TestOpenAnonymousWrongKey(t *testing.T) {
	var alice, eve Keypair
	if err := alice.Generate(); err != nil {
		t.Fatal(err)
	}
	if err := eve.Generate(); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealAnonymous([]byte("secret"), &alice.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAnonymous(sealed, &eve.Public, &eve.Private); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestOpenAnonymousCorrupted(t *testing.T) {
	var kp Keypair
	if err := kp.Generate(); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealAnonymous([]byte("secret"), &kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := OpenAnonymous(sealed, &kp.Public, &kp.Private); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDeriveKeyDeterministicAndSeparated(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)

	k1, err := DeriveKey(seed, "esec-master-v1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(seed, "esec-master-v1")
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("same seed+info must derive the same key")
	}

	other, err := DeriveKey(seed, "esec-identity-v1")
	if err != nil {
		t.Fatal(err)
	}
	if k1 == other {
		t.Fatal("different info strings must derive different keys")
	}

	otherSeed, err := DeriveKey(bytes.Repeat([]byte{0x43}, 32), "esec-master-v1")
	if err != nil {
		t.Fatal(err)
	}
	if k1 == otherSeed {
		t.Fatal("different seeds must derive different keys")
	}
}
