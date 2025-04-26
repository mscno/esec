package commands

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/zalando/go-keyring"
)

type ShareCmd struct {
	KeyName   string   `arg:"" help:"Key to share (e.g. ESEC_PRIVATE_KEY_PROD)"`
	Users     []string `help:"Comma-separated GitHub usernames or IDs to share with" name:"users" sep:","`
	ServerURL string   `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string   `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *ShareCmd) Run(_ *kong.Context) error {
	if c.KeyName == "" || len(c.Users) == 0 {
		return fmt.Errorf("must provide key name and at least one user")
	}
	orgRepo, err := projectfile.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client := client.NewConnectClient(client.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	ctx := context.Background()
	// Fetch current recipients for the key
	perUserPayload, err := client.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull current sharing state: %w", err)
	}
	recipients := map[string]string{} // githubID -> pubKey
	if blobs, ok := perUserPayload[c.KeyName]; ok {
		for githubID := range blobs {
			recipients[githubID] = "" // will fill pubKey below
		}
	}
	// Add new users
	for _, user := range c.Users {
		if _, ok := recipients[user]; ok {
			continue // already shared
		}
		// Fetch public key for user
		pubKey, githubID, _, err := client.GetUserPublicKey(ctx, user)
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
	f, err := os.Open(".esec-keyring")
	if err != nil {
		return fmt.Errorf("failed to open .esec-keyring: %w", err)
	}
	defer f.Close()
	localSecrets, err := godotenv.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse .esec-keyring: %w", err)
	}
	secret, ok := localSecrets[c.KeyName]
	if !ok {
		return fmt.Errorf("key %s not found in .esec-keyring", c.KeyName)
	}
	// Encrypt for each new user
	myPrivHex, err := keyring.Get("esec", "private-key")
	if err != nil {
		return fmt.Errorf("could not get your private key from keyring: %w", err)
	}
	privBytes, err := hex.DecodeString(myPrivHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key format in keyring")
	}
	var priv [32]byte
	copy(priv[:], privBytes)
	myKeypair := &crypto.Keypair{Private: priv}
	newBlobs := map[string]string{}
	for githubID, pubKey := range recipients {
		if pubKey == "" {
			// Already shared, skip
			continue
		}
		var pubArr [32]byte
		pubBytes, err := hex.DecodeString(pubKey)
		if err != nil || len(pubBytes) != 32 {
			fmt.Printf("Invalid public key for %s, skipping\n", githubID)
			continue
		}
		copy(pubArr[:], pubBytes)
		enc := myKeypair.Encrypter(pubArr)
		ciphertext, err := enc.Encrypt([]byte(secret))
		if err != nil {
			fmt.Printf("Encryption failed for %s: %v\n", githubID, err)
			continue
		}
		newBlobs[githubID] = base64.StdEncoding.EncodeToString(ciphertext)
	}
	// Push updated payload
	if len(newBlobs) > 0 {
		if perUserPayload[c.KeyName] == nil {
			perUserPayload[c.KeyName] = map[string]string{}
		}
		for k, v := range newBlobs {
			perUserPayload[c.KeyName][k] = v
		}
		if err := client.PushKeysPerUser(ctx, orgRepo, perUserPayload); err != nil {
			return fmt.Errorf("failed to push updated sharing: %w", err)
		}
		fmt.Println("Shared secret updated for new users.")
	} else {
		fmt.Println("No new users to share with.")
	}
	return nil
}
