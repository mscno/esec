package commands

import (
	"fmt"
	"github.com/mscno/esec/pkg/keys"
	"github.com/zalando/go-keyring"
)

type KeysCmd struct {
	List        KeysListCmd        `cmd:"list" help:"List all pinned user keys and fingerprints."`
	Verify      KeysVerifyCmd      `cmd:"verify" help:"Show the fingerprint for a user and instructions for verification."`
	Fingerprint KeysFingerprintCmd `cmd:"fingerprint" help:"Show your own public key fingerprint for verification."`
}

type KeysListCmd struct{}

type KeysVerifyCmd struct{
	User string `arg:"" help:"GitHub username or ID to verify."`
}

func (c *KeysListCmd) Run(ctx *cliCtx, parent *KeysCmd) error {
	kk, err := keys.LoadKnownKeys()
	if err != nil {
		return err
	}
	fmt.Println("Pinned User Keys:")
	for _, pk := range kk.Keys {
		fmt.Printf("- %s (%s):\n    Fingerprint: %s\n", pk.Username, pk.GitHubID, pk.Fingerprint)
	}
	return nil
}

func (c *KeysVerifyCmd) Run(ctx *cliCtx, parent *KeysCmd) error {
	kk, err := keys.LoadKnownKeys()
	if err != nil {
		return err
	}
	for _, pk := range kk.Keys {
		if pk.Username == c.User || pk.GitHubID == c.User {
			wordPhrase := keys.FingerprintWords(pk.PublicKey)
			fmt.Printf("User: %s (%s)\nFingerprint: %s\nWord phrase: %s\n\nShare this fingerprint or word phrase out-of-band with the user to verify their identity.\n", pk.Username, pk.GitHubID, pk.Fingerprint, wordPhrase)
			return nil
		}
	}
	return fmt.Errorf("User '%s' not found in pinned keys", c.User)
}

type KeysFingerprintCmd struct{}

func (c *KeysFingerprintCmd) Run(ctx *cliCtx, parent *KeysCmd) error {
	// Load public key from keyring
	pubKey, err := keyring.Get("esec", "public-key")
	if err != nil {
		return fmt.Errorf("No public key found in keyring. Please run 'esec auth generate-keypair' first.")
	}
	fp := keys.Fingerprint(pubKey)
	wordPhrase := keys.FingerprintWords(pubKey)
	fmt.Printf("Your public key fingerprint:\n%s\nWord phrase: %s\n\nShare this with teammates so they can verify your key before sharing secrets with you.\n", fp, wordPhrase)
	return nil
}
