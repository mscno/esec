package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tyler-smith/go-bip39"
)

type PinnedKey struct {
	GitHubID    string `json:"github_id"`
	Username    string `json:"username"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type KnownKeys struct {
	Keys map[string]PinnedKey `json:"keys"` // github_id -> PinnedKey
}

func knownKeysPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".esec-known-keys.json")
}

func LoadKnownKeys() (*KnownKeys, error) {
	path := knownKeysPath()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &KnownKeys{Keys: map[string]PinnedKey{}}, nil
		}
		return nil, err
	}
	defer f.Close()
	var kk KnownKeys
	if err := json.NewDecoder(f).Decode(&kk); err != nil {
		return nil, err
	}
	if kk.Keys == nil {
		kk.Keys = map[string]PinnedKey{}
	}
	return &kk, nil
}

func SaveKnownKeys(kk *KnownKeys) error {
	path := knownKeysPath()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(kk)
}

func Fingerprint(pubKey string) string {
	h := sha256.Sum256([]byte(pubKey))
	hexStr := hex.EncodeToString(h[:])
	// Format as groups of 4 chars for readability
	out := ""
	for i := 0; i < len(hexStr); i += 4 {
		if i > 0 {
			out += ":"
		}
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		out += hexStr[i:end]
	}
	return out
}

// FingerprintWords returns a short word phrase (6 words) from the fingerprint using the BIP-39 wordlist
func FingerprintWords(pubKey string) string {
	h := sha256.Sum256([]byte(pubKey))
	words := make([]string, 6)
	for i := 0; i < 6; i++ {
		// Each word index: use 11 bits (2048 words)
		// 6*11 = 66 bits, SHA-256 has enough bits
		bitpos := i * 11
		idx := 0
		for j := 0; j < 11; j++ {
			bytepos := (bitpos + j) / 8
			bitoff := 7 - ((bitpos + j) % 8)
			if (h[bytepos] & (1 << bitoff)) != 0 {
				idx |= (1 << (10 - j))
			}
		}
		words[i] = bip39.GetWordList()[idx]
	}
	return joinWords(words)
}

func joinWords(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += "-"
		}
		out += w
	}
	return out
}

// PinKey adds or updates a pinned key, returns true if new or changed
func (kk *KnownKeys) PinKey(githubID, username, pubKey string) (changed bool, old PinnedKey) {
	fp := Fingerprint(pubKey)
	pk, exists := kk.Keys[githubID]
	if !exists || pk.PublicKey != pubKey {
		kk.Keys[githubID] = PinnedKey{
			GitHubID: githubID,
			Username: username,
			PublicKey: pubKey,
			Fingerprint: fp,
		}
		return true, pk
	}
	return false, pk
}

// GetPinnedKey returns the pinned key for a user, if any
func (kk *KnownKeys) GetPinnedKey(githubID string) (PinnedKey, bool) {
	pk, ok := kk.Keys[githubID]
	return pk, ok
}
