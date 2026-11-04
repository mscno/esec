// Package recovery derives a native age identity from an offline BIP39 phrase.
// It stores nothing and never reads local credentials or contacts a service.
package recovery

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/seal"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	// Format is the version to record with a newly generated recovery phrase.
	Format = "esec-v1"
	// VaultFormat reproduces the old Vault v2 root recovery recipient exactly.
	// This is not the random user identity formerly wrapped inside identity.esec.
	VaultFormat = "vault-v2"
)

// Generate returns 24 English words encoding 256 bits from the OS random source.
func Generate() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	defer clear(entropy)
	return bip39.NewMnemonic(entropy)
}

// Normalize accepts pasted English phrases with case/whitespace differences.
func Normalize(phrase string) string {
	return strings.Join(strings.Fields(strings.ToLower(phrase)), " ")
}

// Derive uses BIP39, Argon2id (64 MiB, 3 passes, 2 lanes), then HKDF-SHA256.
// esec-v1 applies NFKD normalization and a distinct derivation domain. vault-v2
// deliberately preserves the historical passphrase bytes and derivation domain.
// Changing or omitting a nonempty passphrase produces a different identity.
func Derive(phrase, passphrase, format string) (*age.X25519Identity, error) {
	phrase = Normalize(phrase)
	if format != Format && format != VaultFormat {
		return nil, errors.New("unknown recovery format; use esec-v1 or vault-v2")
	}
	if len(strings.Fields(phrase)) != 24 || !bip39.IsMnemonicValid(phrase) {
		return nil, errors.New("invalid recovery phrase: expected 24 English BIP39 words with a valid checksum")
	}
	info := "esec-recovery-age-v1"
	salt := "esec-recovery-derivation-v1"
	if format == VaultFormat {
		info, salt = "esec-master-v2", "esec-identity-derivation-v1"
	} else {
		passphrase = norm.NFKD.String(passphrase)
	}
	seed := bip39.NewSeed(phrase, passphrase)
	defer clear(seed)
	stretched := argon2.IDKey(seed, []byte(salt), 3, 64*1024, 2, 32)
	defer clear(stretched)
	private, err := crypto.DeriveKey(stretched, info)
	if err != nil {
		return nil, err
	}
	defer clear(private[:])
	id, err := seal.X25519Identity(hex.EncodeToString(private[:]))
	if err != nil {
		return nil, fmt.Errorf("derive recovery identity: %w", err)
	}
	return id, nil
}
