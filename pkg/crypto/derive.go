package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// deriveSalt is a fixed, application-wide salt for DeriveKey. Key derivation
// here is deterministic by design: it turns a backed-up secret (e.g. a BIP39
// mnemonic's entropy) into stable key material for recovery.
const deriveSalt = "esec-key-derivation-v1"

// DeriveKey deterministically derives a 32-byte key from seed using
// HKDF-SHA256 with the given info string. Use distinct, versioned info strings
// (e.g. "esec-master-v1") to separate keys derived from the same seed for
// different purposes.
func DeriveKey(seed []byte, info string) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, seed, []byte(deriveSalt), []byte(info))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, err
	}
	return key, nil
}
