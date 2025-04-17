package commands

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/nacl/box"
)

type AuthGenerateKeypairCmd struct{}

func (c *AuthGenerateKeypairCmd) Run(_ *kong.Context) error {
	// Check for existing keypair in keyring
	_, privErr := keyring.Get("esec", "private-key")
	_, pubErr := keyring.Get("esec", "public-key")
	if privErr == nil || pubErr == nil {
		var resp string
		fmt.Print("A keypair already exists in the keyring. Overwrite? [y/N]: ")
		fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("Aborted: keypair not overwritten.")
			return nil
		}
	}
	// 1. Generate 256 bits of entropy
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return fmt.Errorf("failed to generate entropy: %w", err)
	}

	// 2. Generate mnemonic
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// 3. Use entropy as seed for Curve25519 keypair
	var kp crypto.Keypair
	seed := entropy
	if len(seed) != 32 {
		return fmt.Errorf("unexpected seed length: got %d, want 32", len(seed))
	}
	// Use box.GenerateKey with a deterministic reader for Curve25519
	pub, priv, err := box.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return fmt.Errorf("failed to deterministically generate keypair: %w", err)
	}
	kp.Public = *pub
	kp.Private = *priv

	// 4. Store private and public key in keyring
	err = keyring.Set("esec", "private-key", hex.EncodeToString(kp.Private[:]))
	if err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	err = keyring.Set("esec", "public-key", hex.EncodeToString(kp.Public[:]))
	if err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	// 5. Print mnemonic for user, formatted clearly
	fmt.Println("\n============================================================")
	fmt.Println("                    YOUR RECOVERY PHRASE")
	fmt.Println("============================================================")

	words := strings.Fields(mnemonic)
	for i, word := range words {
		fmt.Printf("%s", word)
		if (i+1)%8 == 0 || i == len(words)-1 {
			fmt.Println()
		} else {
			fmt.Print(" ")
		}
	}
	fmt.Println("\n============================================================")
	fmt.Println("Store this phrase securely. It can be used to restore your key on another device.")
	fmt.Println("============================================================\n")

	return nil
}
