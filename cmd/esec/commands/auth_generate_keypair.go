package commands

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mscno/esec/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/nacl/box"
)

type AuthGenerateKeypairCmd struct{}

func (c *AuthGenerateKeypairCmd) Run(ctx *cliCtx) error {
	// Check for existing keypair in keyring
	_, privErr := ctx.OSKeyring.Get("esec", "private-key")
	_, pubErr := ctx.OSKeyring.Get("esec", "public-key")
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
	privHex := hex.EncodeToString(kp.Private[:])
	pubHex := hex.EncodeToString(kp.Public[:])
	err = ctx.OSKeyring.Set("esec", "private-key", privHex)
	if err != nil {
		return fmt.Errorf("failed to save private key to keyring: %w", err)
	}
	err = ctx.OSKeyring.Set("esec", "public-key", pubHex)
	if err != nil {
		// Attempt to remove private key if public key saving failed
		_ = ctx.OSKeyring.Delete("esec", "private-key")
		return fmt.Errorf("failed to save public key to keyring: %w", err)
	}

	// 5. Print mnemonic for user, formatted clearly
	fmt.Print(`
============================================================
                    YOUR RECOVERY PHRASE
============================================================

`)

	words := strings.Fields(mnemonic)
	for i, word := range words {
		fmt.Printf("%s", word)
		if (i+1)%8 == 0 || i == len(words)-1 {
			fmt.Println()
		} else {
			fmt.Print(" ")
		}
	}
	fmt.Print(`
============================================================
Store this phrase securely. It can be used to restore your key on another device.
============================================================
`)

	return nil
}
