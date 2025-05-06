package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/mscno/esec/pkg/client"
	"os"
	"path"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/projectfile"
)

type ShareCmd struct {
	KeyName client.PrivateKeyName `arg:"" help:"Key to share (e.g. ESEC_PRIVATE_KEY_PROD)"`
	Users   []string              `help:"Comma-separated GitHub usernames or IDs to share with" name:"users" sep:","`
}

func (c *ShareCmd) Run(ctx *cliCtx, parent *CloudCmd) error {
	if c.KeyName == "" || len(c.Users) == 0 {
		return fmt.Errorf("must provide key name and at least one user")
	}
	orgRepo, err := projectfile.ReadProjectFile(parent.ProjectDir)
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}

	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, parent)
	if err != nil {
		return err
	}

	// Fetch current recipients for the key
	perUserPayload, err := connectClient.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull current sharing state: %w", err)
	}
	recipients := map[string]string{} // githubID -> pubKey

	for githubId, secrets := range perUserPayload {
		if _, ok := secrets[c.KeyName]; ok {
			recipients[githubId.String()] = ""
		}
	}

	// Add new users
	for _, user := range c.Users {
		if _, ok := recipients[user]; ok {
			continue // already shared
		}
		// Fetch public key for user
		pubKey, githubID, _, err := connectClient.GetUserPublicKey(ctx, client.UserId(user))
		if err != nil {
			fmt.Printf("Could not fetch key for %s: %v. Skipping.\n", user, err)
			continue
		}
		recipients[githubID] = pubKey
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no valid users to share with")
	}
	// Load secret value from local keyring
	keyringPath := path.Join(parent.ProjectDir, ".esec-keyring")

	f, err := os.Open(keyringPath)
	if err != nil {
		return fmt.Errorf("failed to open .esec-keyring: %w", err)
	}
	defer f.Close()
	localSecrets, err := godotenv.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse .esec-keyring: %w", err)
	}
	secret, ok := localSecrets[c.KeyName.String()]
	if !ok {
		return fmt.Errorf("key %s not found in .esec-keyring", c.KeyName)
	}
	// Encrypt for each new user
	myPrivHex, err := ctx.OSKeyring.Get("esec", "private-key")
	if err != nil {
		return fmt.Errorf("could not get your private key from keyring: %w", err)
	}
	privBytes, err := hex.DecodeString(myPrivHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key format in keyring")
	}
	var priv [32]byte
	copy(priv[:], privBytes)

	newBlobs := map[string]string{}
	for githubID, pubKey := range recipients {
		if pubKey == "" {
			// Already shared, skip
			continue
		}
		var kp crypto.Keypair
		err = kp.Generate()
		if err != nil {
			return err
		}

		// Create an encrypter using the public key extracted from the input data
		var pubArr [32]byte
		pubBytes, err := hex.DecodeString(pubKey)
		if err != nil || len(pubBytes) != 32 {
			fmt.Printf("Invalid public key for %s, skipping\n", githubID)
			continue
		}
		copy(pubArr[:], pubBytes)
		enc := kp.Encrypter(pubArr)

		ciphertext, err := enc.Encrypt([]byte(secret))
		if err != nil {
			fmt.Printf("Encryption failed for %s: %v\n", githubID, err)
			continue
		}
		newBlobs[githubID] = base64.StdEncoding.EncodeToString(ciphertext)
	}
	if len(newBlobs) > 0 {
		// Create a payload in the format expected by connectClient.PushKeysPerUser
		payload := make(map[client.UserId]map[client.PrivateKeyName]string)
		for githubID, ciphertext := range newBlobs {
			userID := client.UserId(githubID)
			if _, ok := payload[userID]; !ok {
				payload[userID] = make(map[client.PrivateKeyName]string)
			}
			payload[userID][c.KeyName] = ciphertext
		}
		if err := connectClient.PushKeysPerUser(ctx, orgRepo, payload); err != nil {
			return fmt.Errorf("failed to push updated sharing: %w", err)
		}
		fmt.Println("Shared secret updated for new users.")
	} else {
		fmt.Println("No new users to share with.")
	}
	return nil
}
