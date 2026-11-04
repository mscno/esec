package recovery

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestRecoveryDerivationAndValidation(t *testing.T) {
	phrase, err := bip39.NewMnemonic(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Derive(phrase, "", Format)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Derive("  "+strings.ToUpper(strings.ReplaceAll(phrase, " ", "\t"))+"\n", "", Format)
	if err != nil || first.String() != again.String() {
		t.Fatal("normalized phrase changed identity", err)
	}
	protected, err := Derive(phrase, "correct horse", Format)
	if err != nil || first.String() == protected.String() {
		t.Fatal("passphrase must change identity", err)
	}
	composed, err := Derive(phrase, "café", Format)
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := Derive(phrase, "cafe\u0301", Format)
	if err != nil || composed.String() != decomposed.String() {
		t.Fatal("NFKD normalization changed identity", err)
	}
	legacy, err := Derive(phrase, "", VaultFormat)
	if err != nil || legacy.String() == first.String() {
		t.Fatal("derivation formats must be distinct", err)
	}
	for _, bad := range []string{"", strings.Repeat("abandon ", 24), "not a generated recovery phrase", strings.Repeat("abandon ", 11) + "about"} {
		if _, err := Derive(bad, "", Format); err == nil {
			t.Fatal("invalid phrase accepted")
		}
	}
	if _, err := Derive(phrase, "", "unknown"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestVaultRootCompatibilityVectors(t *testing.T) {
	// Independently generated with esec-vault v0.30.0 identity.DeriveMasterKeys,
	// from the public all-zero 256-bit BIP39 test entropy. No real credentials.
	phrase, err := bip39.NewMnemonic(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]string{
		"":       "age1g9feqfgtyh7qj3xlwjtkx7h6mk2w9c8y53dyhjh4meq7p4yhk4js9y33cv",
		"TREZOR": "age1v239mpgeu9uyhgh4r6mhcl4edn3qe0lk0yrwey0xu3l8azsy3srsxslzxn",
		"café":   "age17k58a7x5as23l827x9tagffn9x2n28dx8trv0t2tjnscjfq0ycgqarqaet",
	}
	for pass, expected := range vectors {
		id, err := Derive(phrase, pass, VaultFormat)
		if err != nil || id.Recipient().String() != expected {
			t.Fatal("legacy root recipient compatibility failed", err)
		}
	}
}

func TestGenerate24Words(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(strings.Fields(a)) != 24 || !bip39.IsMnemonicValid(a) {
		t.Fatal("invalid generated recovery phrase")
	}
}

func TestV1FormatRemainsStable(t *testing.T) {
	phrase, err := bip39.NewMnemonic(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]string{
		"":       "age1fe75xaqxj2rk5y05umcu9rpm8h0gd70ad33zjrg9ks5m0p9wpcesraulc6",
		"TREZOR": "age19znpg63jwzxd803c7t9uejuwe8r03z2v9gv8ayucuddszfnp7qcqkekkvn",
	}
	for pass, expected := range vectors {
		id, err := Derive(phrase, pass, Format)
		if err != nil || id.Recipient().String() != expected {
			t.Fatal("esec-v1 recovery format changed", err)
		}
	}
}
