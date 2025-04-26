package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/client"
	"net/http"
	"os"
	"path"
	"strings"

	eseckeyring "github.com/mscno/esec/pkg/keyring"
	"github.com/mscno/esec/pkg/projectfile"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/crypto"
)

type SyncCmd struct {
	Push SyncPushCmd `cmd:"" help:"Push private keys in .esec-keyring to the server"`
	Pull SyncPullCmd `cmd:"" help:"Pull private keys from the server into .esec-keyring"`
}

type SyncPushCmd struct {
}
type SyncPullCmd struct {
}

func (c *SyncPushCmd) Run(ctx *cliCtx, parent *SyncCmd, cloud *CloudCmd) error {
	keyringPath := path.Join(cloud.ProjectDir, ".esec-keyring")

	// Read org/repo from .esec-project
	orgRepo, err := projectfile.ReadProjectFile(cloud.ProjectDir)
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	token, err := ctx.OSKeyring.Get(auth.ServiceName, auth.AccountName)
	if err != nil {
		return fmt.Errorf("failed to get service account token: %w", err)
	}

	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err
	}
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
		if strings.HasPrefix(k, esec.EsecPrivateKey) {
			privateKeys[k] = v
		}
	}

	// --- Recipient logic: fetch from server, fallback to self ---
	// Load sender keypair from OS keyring using injected service
	privHex, privErr := ctx.OSKeyring.Get("esec", "private-key")
	pubHex, pubErr := ctx.OSKeyring.Get("esec", "public-key")
	if privErr != nil || pubErr != nil {
		return fmt.Errorf("could not find your keypair in the OS keyring. Please run 'esec auth generate-keypair' first.")
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key in keyring")
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 32 {
		return fmt.Errorf("invalid public key in keyring")
	}
	var privArr, pubArr [32]byte
	copy(privArr[:], privBytes)
	copy(pubArr[:], pubBytes)
	myKeypair := &crypto.Keypair{Private: privArr, Public: pubArr}

	getSelf := func() (myGitHubID, pubHex string, err error) {
		myGitHubID, err = getGitHubIDFromToken(token)
		if err != nil {
			return "", "", fmt.Errorf("could not determine your GitHub ID: %w", err)
		}
		pubHex, pubErr := ctx.OSKeyring.Get("esec", "public-key")
		if pubErr != nil {
			return "", "", fmt.Errorf("could not find your public key in the OS keyring. Please run 'esec auth generate-keypair' first.")
		}
		return myGitHubID, pubHex, nil
	}

	// Fetch current recipients from server
	perUserPayloadServer, err := connectClient.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		perUserPayloadServer = map[client.UserId]map[client.PrivateKeyName]string{} // fallback to empty
	}

	EncryptForRecipient := func(pubKey, plaintext string) (string, error) {
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

	perUserPayload := map[client.UserId]map[client.PrivateKeyName]string{}
	myGitHubID, myPubHex, err := getSelf()
	if err != nil {
		return err
	}

	for keyName, secret := range privateKeys {
		typedKey := client.PrivateKeyName(keyName)
		recipients := map[client.UserId]string{} // githubID -> pubKey
		for githubID, blobs := range perUserPayloadServer {
			// Fetch public key for recipient
			if githubID.String() == myGitHubID {
				recipients[githubID] = myPubHex
				continue
			}
			if blobs, ok := blobs[typedKey]; ok && len(blobs) > 0 {
				// Use existing recipient list from server

				pubKey, gid, _, err := connectClient.GetUserPublicKey(ctx, githubID)
				if err != nil || gid == "" {
					fmt.Printf("Warning: could not fetch public key for recipient %s: %v. Skipping.\n", githubID, err)
					continue
				}
				recipients[githubID] = pubKey

			} else {
				// Only self
				recipients[client.UserId(myGitHubID)] = myPubHex
			}
		}
		for githubID, pubKey := range recipients {
			if perUserPayload[githubID] == nil {
				perUserPayload[githubID] = map[client.PrivateKeyName]string{}
			}

			encrypted, err := EncryptForRecipient(pubKey, secret)
			if err != nil {
				fmt.Printf("Encryption failed for %s/%s: %v\n", keyName, githubID, err)
				continue
			}
			perUserPayload[githubID][typedKey] = encrypted
		}
	}
	fmt.Printf("Prepared encrypted payload: %+v\n", perUserPayload)
	// Push perUserPayload to server with new API
	if err := connectClient.PushKeysPerUser(ctx, orgRepo, perUserPayload); err != nil {
		return fmt.Errorf("failed to push secrets: %w", err)
	}

	formatted := eseckeyring.FormatKeyringFile(envs)
	err = os.WriteFile(keyringPath, []byte(formatted), 0600)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", keyringPath, err)
	}

	fmt.Println("Pushed encrypted secrets to server.")
	return nil
}

func getGitHubIDFromToken(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	var user struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", err
	}
	if user.ID == 0 {
		return "", fmt.Errorf("GitHub user id not found in response")
	}
	return fmt.Sprintf("%d", user.ID), nil
}

func (c *SyncPullCmd) Run(ctx *cliCtx, parent *SyncCmd, cloud *CloudCmd) error {
	keyringPath := path.Join(cloud.ProjectDir, ".esec-keyring")
	// Read org/repo from .esec-project
	orgRepo, err := projectfile.ReadProjectFile(cloud.ProjectDir)
	if err != nil {
		return fmt.Errorf("failed to read .esec-project: %w", err)
	}
	token, err := ctx.OSKeyring.Get(auth.ServiceName, auth.AccountName)
	if err != nil {
		return fmt.Errorf("failed to get service account token: %w", err)
	}
	// Setup client using the helper function
	connectClient, err := setupConnectClient(ctx, cloud)
	if err != nil {
		return err
	}

	// Fetch per-user encrypted blobs
	perUserPayload, err := connectClient.PullKeysPerUser(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to pull per-user secrets: %w", err)
	}

	// Load our own GitHub ID (from env or token)
	myGitHubID := os.Getenv("ESEC_GITHUB_ID")
	if myGitHubID == "" {
		// Try to fetch from GitHub API using token
		id, err := getGitHubIDFromToken(token)
		if err != nil {
			return fmt.Errorf("could not determine GitHub ID from token: %w", err)
		}
		myGitHubID = id
	}
	// Load our private key from OS keyring using injected service
	privHex, privErr := ctx.OSKeyring.Get("esec", "private-key")
	if privErr != nil {
		return fmt.Errorf("could not find your private key in the OS keyring. Please run 'esec auth generate-keypair' first.")
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid private key format in keyring")
	}
	var priv [32]byte
	copy(priv[:], privBytes)
	myKeypair := &crypto.Keypair{Private: priv}

	// Prepare new keyring map
	newKeyring := map[string]string{}
	for userId, userBlobs := range perUserPayload {
		if userId.String() != myGitHubID {
			continue
		}
		for keyName, blob := range userBlobs {
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
			newKeyring[keyName.String()] = string(plaintext)
		}
	}
	// Merge with existing keyring
	merged := map[string]string{}
	// Parse existing file if present
	if f, err := os.Open(keyringPath); err == nil {
		existing, err := godotenv.Parse(f)
		f.Close()
		if err == nil {
			for k, v := range existing {
				merged[k] = v
			}
		}
	}
	// Overwrite/add fetched keys
	for k, v := range newKeyring {
		if existing, ok := merged[k]; ok && existing != v {
			fmt.Printf("Key %q already exists in %q with value: %q, overwrite with: %q? (y/N): ", k, keyringPath, existing, v)
			var confirm string
			fmt.Scanf("%s", &confirm)
			if strings.ToLower(confirm) != "y" {
				fmt.Printf("Skipping key %s.\n", k)
				continue
			}
		}
		merged[k] = v
	}
	// Write merged map using dotenv.FormatKeyringFile for proper formatting
	formatted := eseckeyring.FormatKeyringFile(merged)
	err = os.WriteFile(keyringPath, []byte(formatted), 0600)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", keyringPath, err)
	}
	fmt.Println("Pulled and decrypted secrets for your user.")
	return nil
}

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
