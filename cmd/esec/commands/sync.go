package commands

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/crypto"
	"github.com/mscno/esec/pkg/keys"
	"github.com/mscno/esec/pkg/project"
	"github.com/mscno/esec/pkg/sync"
)

type SyncCmd struct {
	Push SyncPushCmd `cmd:"" help:"Push private keys in .esec-keyring to the server"`
	Pull SyncPullCmd `cmd:"" help:"Pull private keys from the server into .esec-keyring"`
}

type SyncPushCmd struct {
	ServerURL string   `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string   `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
	ShareWith []string `help:"Comma-separated GitHub usernames or IDs to share secrets with" name:"share-with" sep:","`
}
type SyncPullCmd struct {
	ServerURL string `help:"Sync server URL" env:"ESEC_SERVER_URL" default:"http://localhost:8080"`
	AuthToken string `help:"Auth token (GitHub)" env:"ESEC_AUTH_TOKEN"`
}

func (c *SyncPushCmd) Run(_ *kong.Context) error {
	// Read org/repo from .esec-project
	orgRepo, err := project.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	// Retrieve token from keyring if not provided
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required for CreateProject (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client, err := sync.NewAPIClient(sync.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	if err != nil {
		return fmt.Errorf("failed to create sync client: %w", err)
	}

	keyringPath := ".esec-keyring"
	f, err := os.Open(keyringPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", keyringPath, err)
	}
	defer f.Close()
	envs, err := godotenv.Parse(f)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", keyringPath, err)
	}
	privateKeys := map[string]string{}
	for k, v := range envs {
		if strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
			privateKeys[k] = v
		}
	}

	// --- Key Sharing: Recipient Key Pinning and Verification ---
	trustedRecipients := map[string]string{} // github_id -> public_key
	if len(c.ShareWith) > 0 {
		for _, user := range c.ShareWith {
			fmt.Printf("Fetching public key for %s...\n", user)
			pubKey, githubID, username, err := client.GetUserPublicKey(context.Background(), user)
			if err != nil {
				fmt.Printf("Could not fetch key for %s: %v. Skipping.\n", user, err)
				continue
			}
			kk, _ := keys.LoadKnownKeys()
			changed, old := kk.PinKey(githubID, username, pubKey)
			if changed {
				if old.PublicKey != "" {
					fmt.Printf("\nWARNING: Public key for %s (id: %s) has changed!\nOld fingerprint: %s\nNew fingerprint: %s\nWord phrase: %s\n",
						username, githubID, old.Fingerprint, keys.Fingerprint(pubKey), keys.FingerprintWords(pubKey))
					fmt.Print("Do you want to trust this new key? (y/N): ")
					var resp string
					fmt.Scanln(&resp)
					if len(resp) == 0 || (resp[0] != 'y' && resp[0] != 'Y') {
						fmt.Printf("Skipping sharing to %s\n", username)
						continue
					}
				}
				_ = keys.SaveKnownKeys(kk)
				fmt.Printf("\nPinned public key for %s (%s).\nFingerprint: %s\nWord phrase: %s\nShare this with the user for verification.\n",
					username, githubID, keys.Fingerprint(pubKey), keys.FingerprintWords(pubKey))
			}
			trustedRecipients[githubID] = pubKey
		}
	} else {
		fmt.Println("No recipients specified with --share-with; will only encrypt for yourself.")
	}

	// --- Encryption logic ---
	// Encrypt each private key for each trusted recipient using NaCl box (pkg/crypto)
	var myKeypair *crypto.Keypair
	// Try to load sender keypair from .esec-keyring
	for k, v := range envs {
		if k == "ESEC_PRIVATE_KEY_SELF" || (k == "ESEC_PRIVATE_KEY" && myKeypair == nil) {
			// Parse hex encoded key (private key only)
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				continue
			}
			var priv [32]byte
			copy(priv[:], b)
			kp := &crypto.Keypair{Private: priv}
			myKeypair = kp
		}
	}
	if myKeypair == nil {
		return fmt.Errorf("could not find your own private key in .esec-keyring (ESEC_PRIVATE_KEY_SELF or ESEC_PRIVATE_KEY)")
	}

	EncryptForRecipient := func(pubKey, plaintext string) (string, error) {
		// Parse recipient public key (expect hex-encoded 32 bytes)
		pubBytes, err := hex.DecodeString(pubKey)
		if err != nil || len(pubBytes) != 32 {
			return "", fmt.Errorf("invalid recipient public key: %v", err)
		}
		var pubArr [32]byte
		copy(pubArr[:], pubBytes)
		enc := crypto.NewEncrypter(myKeypair, pubArr)
		ciphertext, err := enc.Encrypt([]byte(plaintext))
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(ciphertext), nil
	}

	// Prepare nested map: secret_key -> github_id -> encrypted_blob
	perUserPayload := map[string]map[string]string{}
	for keyName, secret := range privateKeys {
		perUserPayload[keyName] = map[string]string{}
		for githubID, pubKey := range trustedRecipients {
			encrypted, err := EncryptForRecipient(pubKey, secret)
			if err != nil {
				fmt.Printf("Encryption failed for %s/%s: %v\n", keyName, githubID, err)
				continue
			}
			perUserPayload[keyName][githubID] = encrypted
		}
	}
	fmt.Printf("Prepared encrypted payload: %+v\n", perUserPayload)
	// Push perUserPayload to server with new API
	ctx := context.Background()
	if err := client.PushKeysPerUser(ctx, orgRepo, perUserPayload); err != nil {
		return fmt.Errorf("failed to push secrets: %w", err)
	}
	fmt.Println("Pushed encrypted secrets to server.")
	return nil
}

func (c *SyncPullCmd) Run(_ *kong.Context) error {
	keyringPath := ".esec-keyring"
	// Read org/repo from .esec-project
	orgRepo, err := project.ReadProjectFile(".")
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	// Retrieve token from keyring if not provided
	if c.AuthToken == "" {
		provider := auth.NewGithubProvider(auth.Config{})
		token, err := provider.GetToken(context.Background())
		if err != nil || token == "" {
			return fmt.Errorf("authentication token required for CreateProject (login with 'esec auth login')")
		}
		c.AuthToken = token
	}
	client, err := sync.NewAPIClient(sync.ClientConfig{
		ServerURL: c.ServerURL,
		AuthToken: c.AuthToken,
	})
	if err != nil {
		return fmt.Errorf("failed to create sync client: %w", err)
	}
	ctx := context.Background()
	// Fetch per-user encrypted blobs
	perUserPayload, err := client.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull per-user secrets: %w", err)
	}

	// Load our own GitHub ID (from token or config)
	myGitHubID := os.Getenv("ESEC_GITHUB_ID")
	if myGitHubID == "" {
		return fmt.Errorf("ESEC_GITHUB_ID environment variable not set (needed for decryption)")
	}
	// Load our private key
	privHex := ""
	f, err := os.Open(keyringPath)
	if err == nil {
		envs, _ := godotenv.Parse(f)
		f.Close()
		if v, ok := envs["ESEC_PRIVATE_KEY"]; ok {
			privHex = v
		}
	}
	if privHex == "" {
		return fmt.Errorf("ESEC_PRIVATE_KEY not found in .esec-keyring")
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key format")
	}
	var priv [32]byte
	copy(priv[:], privBytes)
	myKeypair := &crypto.Keypair{Private: priv}

	// Prepare new keyring map
	newKeyring := map[string]string{}
	for keyName, userBlobs := range perUserPayload {
		blob, ok := userBlobs[myGitHubID]
		if !ok {
			fmt.Printf("No secret for your user (%s) for key %s\n", myGitHubID, keyName)
			continue
		}
		ciphertext, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			fmt.Printf("Failed to decode ciphertext for %s: %v\n", keyName, err)
			continue
		}
		decrypter := myKeypair.Decrypter()
		plaintext, err := decrypter.Decrypt(ciphertext)
		if err != nil {
			fmt.Printf("Failed to decrypt secret %s: %v\n", keyName, err)
			continue
		}
		newKeyring[keyName] = string(plaintext)
	}
	// Write new keyring
	f, err = os.Create(keyringPath)
	if err != nil {
		return fmt.Errorf("failed to write new keyring: %w", err)
	}
	for k, v := range newKeyring {
		fmt.Fprintf(f, "%s=%s\n", k, v)
	}
	f.Close()
	fmt.Println("Pulled and decrypted secrets for your user.")
	return nil
}

// 	// Write new keyring: active keys first, then private keys

// 	// Only keep active and private keys for writing
// 	filtered := map[string]string{}
// 	for k, v := range lines {
// 		if strings.HasPrefix(k, "ESEC_ACTIVE") || strings.HasPrefix(k, "ESEC_PRIVATE_KEY") {
// 			filtered[k] = v
// 		}
// 	}
// 	formatted := dotenv.FormatKeyringFile(filtered)
// 	if err := os.WriteFile(keyringPath, []byte(formatted), 0600); err != nil {
// 		return fmt.Errorf("failed to write %s: %w", keyringPath, err)
// 	}
// 	fmt.Println("Pulled private keys from server and updated .esec-keyring.")
// 	return nil
// }
