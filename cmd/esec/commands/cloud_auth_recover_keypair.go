package commands

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/nacl/box"
)

type AuthRecoverKeypairCmd struct{}

func (c *AuthRecoverKeypairCmd) Run(ctx *cliCtx) error {
	fmt.Println("Paste your 24-word BIP39 recovery phrase (separated by spaces):")
	reader := bufio.NewReader(os.Stdin)
	mnemonic, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
	}
	mnemonic = strings.TrimSpace(mnemonic)
	// Normalize whitespace: replace all whitespace with single spaces
	mnemonic = strings.Join(strings.Fields(mnemonic), " ")
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		fmt.Printf("Expected 24 words, got %d.\n", len(words))
		return fmt.Errorf("invalid BIP39 mnemonic: must be exactly 24 words")
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid BIP39 mnemonic")
	}
	entropy, err := bip39.MnemonicToByteArray(mnemonic, true)
	if err != nil {
		return fmt.Errorf("failed to convert mnemonic to entropy: %w", err)
	}
	if len(entropy) != 32 {
		return fmt.Errorf("unexpected entropy length: got %d, want 32", len(entropy))
	}
	pub, priv, err := box.GenerateKey(bytes.NewReader(entropy))
	if err != nil {
		return fmt.Errorf("failed to deterministically generate keypair: %w", err)
	}
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
	privHex := hex.EncodeToString(priv[:])
	pubHex := hex.EncodeToString(pub[:])
	err = ctx.OSKeyring.Set("esec", "private-key", privHex)
	if err != nil {
		return fmt.Errorf("failed to save private key to keyring: %w", err)
	}
	err = ctx.OSKeyring.Set("esec", "public-key", pubHex)
	if err != nil {
		_ = ctx.OSKeyring.Delete("esec", "private-key")
		return fmt.Errorf("failed to save public key to keyring: %w", err)
	}
	fmt.Println("Keypair successfully recovered and stored in keyring.")
	return nil
}
