// Package keyringfile reads and writes esec keyring files, plain or sealed.
//
// A plain keyring is a dotenv file of ESEC_PRIVATE_KEY* entries. A sealed
// keyring holds the same dotenv text encrypted under a per-device cache key
// kept in the secret store (see package secretstore):
//
//	ESEC-SEALED-KEYRING-V1
//	base64( nonce(24) || XChaCha20-Poly1305(cacheKey, plain,
//	        aad = "esec-keyring/v1\n" + file basename) )
//
// The first line is chosen so that esec versions without sealed-keyring
// support fail to parse the file instead of treating it as empty: godotenv
// rejects the '-' characters in what it reads as a variable name.
//
// The basename in the associated data binds the ciphertext to its file name,
// so one project's sealed keyring cannot be swapped in for another's.
package keyringfile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/mscno/esec/pkg/filelock"
	"github.com/mscno/esec/pkg/secretstore"
)

// Magic is the first line of every sealed keyring.
const Magic = "ESEC-SEALED-KEYRING-V1"

// CacheKeyName is the secret store entry holding the keyring cache key.
const CacheKeyName = "keyring-cache-key"

// Capability is printed by `esec capabilities` when this format is supported.
const Capability = "sealed-keyring-v1"

// ErrCacheKey is returned when a sealed keyring is found but the cache key is
// not available on this machine.
var ErrCacheKey = errors.New("keyring is sealed but this machine's keyring cache key is not available")

// ErrSealed is returned when a sealed keyring cannot be opened.
var ErrSealed = errors.New("sealed keyring could not be opened")

// IsSealed reports whether data is a sealed keyring.
func IsSealed(data []byte) bool {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return string(bytes.TrimSuffix(line, []byte("\r"))) == Magic
}

func aad(name string) []byte { return []byte("esec-keyring/v1\n" + filepath.Base(name)) }

// Seal encrypts plain keyring text under key, bound to the file name.
func Seal(plain []byte, key *[32]byte, name string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nonce, nonce, plain, aad(name))
	var out bytes.Buffer
	out.WriteString(Magic)
	out.WriteByte('\n')
	out.WriteString(base64.StdEncoding.EncodeToString(sealed))
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Open decrypts a sealed keyring, checking that it was sealed for name.
func Open(data []byte, key *[32]byte, name string) ([]byte, error) {
	if !IsSealed(data) {
		return nil, fmt.Errorf("%w: missing %s header", ErrSealed, Magic)
	}
	_, rest, _ := bytes.Cut(data, []byte("\n"))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rest)))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: bad encoding", ErrSealed, filepath.Base(name))
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("%w: %s: truncated", ErrSealed, filepath.Base(name))
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], aad(name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: wrong cache key, wrong file name, or modified file", ErrSealed, filepath.Base(name))
	}
	return plain, nil
}

// CacheKey loads the cache key from store.
func CacheKey(store secretstore.Store) (*[32]byte, error) {
	v, err := store.Get(CacheKeyName)
	if err != nil {
		if errors.Is(err, secretstore.ErrNotFound) {
			return nil, ErrCacheKey
		}
		return nil, fmt.Errorf("%w: %v", ErrCacheKey, err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%w: stored cache key is malformed", ErrCacheKey)
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

// EnsureCacheKey loads the cache key, creating and storing one if absent.
// Creation happens under a cross-process lock and re-reads afterwards, so
// two first-time writers never seal with different keys.
func EnsureCacheKey(store secretstore.Store) (*[32]byte, error) {
	if k, err := CacheKey(store); err == nil {
		return k, nil
	}
	unlock, err := lockCacheKey()
	if err != nil {
		return nil, err
	}
	defer unlock()
	k, err := CacheKey(store)
	if err == nil {
		return k, nil
	}
	if _, getErr := store.Get(CacheKeyName); !errors.Is(getErr, secretstore.ErrNotFound) {
		return nil, err
	}
	var nk [32]byte
	if _, err := rand.Read(nk[:]); err != nil {
		return nil, err
	}
	if err := store.Set(CacheKeyName, hex.EncodeToString(nk[:])); err != nil {
		return nil, err
	}
	return CacheKey(store)
}

// lockCacheKey waits up to ten seconds for the cache-key creation lock.
func lockCacheKey() (func(), error) {
	dir := filepath.Join(secretstore.Home(), "locks", "cache-key")
	deadline := time.Now().Add(10 * time.Second)
	for {
		unlock, err := filelock.Acquire(dir)
		if err == nil {
			return unlock, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Codec decodes and encodes keyring files. A nil Store means the default
// secret store, opened only when a sealed file is met.
type Codec struct {
	Store secretstore.Store
}

// Decode returns the plain keyring text of the file at path with content data.
// Plain files are returned unchanged.
func (c Codec) Decode(path string, data []byte) ([]byte, error) {
	if !IsSealed(data) {
		return data, nil
	}
	s, err := c.store()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, err := CacheKey(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (backend %q; run 'esec vault status')", path, err, s.Backend())
	}
	return Open(data, key, path)
}

// Parse decodes the file and parses its dotenv entries.
func (c Codec) Parse(path string, data []byte) (map[string]string, error) {
	plain, err := c.Decode(path, data)
	if err != nil {
		return nil, err
	}
	return godotenv.Parse(bytes.NewReader(plain))
}

// Encode returns the bytes to write for plain keyring text, sealed when asked.
func (c Codec) Encode(path string, plain []byte, sealed bool) ([]byte, error) {
	if !sealed {
		return plain, nil
	}
	s, err := c.store()
	if err != nil {
		return nil, err
	}
	key, err := EnsureCacheKey(s)
	if err != nil {
		return nil, err
	}
	return Seal(plain, key, path)
}

// SealNewByDefault reports whether newly created keyrings should be sealed,
// per secret-store.toml.
func SealNewByDefault() bool {
	c, err := secretstore.LoadConfig()
	return err == nil && c.SealKeyrings
}

// Parse decodes and parses a keyring with the default secret store.
func Parse(path string, data []byte) (map[string]string, error) {
	return Codec{}.Parse(path, data)
}

// Decode returns plain keyring text using the default secret store.
func Decode(path string, data []byte) ([]byte, error) {
	return Codec{}.Decode(path, data)
}

func (c Codec) store() (secretstore.Store, error) {
	if c.Store != nil {
		return c.Store, nil
	}
	s, err := secretstore.Default()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCacheKey, err)
	}
	return s, nil
}
