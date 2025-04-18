package commands

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/tyler-smith/go-bip39"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/nacl/box"
)

type AuthRecoverKeypairCmd struct{}

func (c *AuthRecoverKeypairCmd) Run(_ *kong.Context) error {
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
	if err := keyring.Set("esec", "private-key", hex.EncodeToString(priv[:])); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := keyring.Set("esec", "public-key", hex.EncodeToString(pub[:])); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}
	fmt.Println("Keypair successfully recovered and stored in keyring.")
	return nil
}
