// Package format provides common types and utilities for handling encrypted file formats.
package format

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Public key field names used in encrypted files.
const (
	// PublicKeyField is the standard key name for the public key in encrypted files.
	PublicKeyField = "ESEC_PUBLIC_KEY"
	// UnderscoredPublicKeyField is the alternative key name (with underscore prefix)
	// that prevents the key itself from being encrypted in JSON format.
	UnderscoredPublicKeyField = "_ESEC_PUBLIC_KEY"
)

// Handler defines the interface for format-specific encryption/decryption handlers.
// Each supported file format (dotenv, JSON, etc.) implements this interface.
type Handler interface {
	// TransformScalarValues walks the data and applies the given function to each
	// encryptable value. The function is typically an encrypt or decrypt operation.
	TransformScalarValues(data []byte, fn func([]byte) ([]byte, error)) ([]byte, error)
	// ExtractPublicKey parses the data and returns the embedded public key.
	ExtractPublicKey(data []byte) ([32]byte, error)
}

// ErrPublicKeyMissing indicates that the PublicKeyField key was not found
// at the top level of the JSON document provided.
var ErrPublicKeyMissing = errors.New("public key not present in ecfg file")

// ErrPublicKeyInvalid means that the PublicKeyField key was found, but the
// value could not be parsed into a valid key.
var ErrPublicKeyInvalid = errors.New("public key has invalid format")

// ExtractPublicKeyHelper extracts the public key from a parsed data structure.
// It looks for either "_ESEC_PUBLIC_KEY" (preferred) or "ESEC_PUBLIC_KEY" fields.
// The type parameter T allows this to work with both map[string]interface{} and map[string]string.
func ExtractPublicKeyHelper[T any](obj map[string]T) ([32]byte, error) {
	var (
		ks string
		ok bool
	)
	var k interface{}
	k, ok = obj[UnderscoredPublicKeyField]
	if !ok {
		k, ok = obj[PublicKeyField]
		if !ok {
			return [32]byte{}, ErrPublicKeyMissing
		}
	}

	ks, ok = k.(string)
	if !ok {
		return [32]byte{}, fmt.Errorf("%w: public key is not a string", ErrPublicKeyInvalid)
	}

	key, err := ParseKey(ks)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrPublicKeyInvalid, err)
	}

	return key, nil
}

// ParseKey parses a hex-encoded 32-byte key string into a [32]byte array.
// The input must be exactly 64 hex characters (representing 32 bytes).
func ParseKey(ks string) ([32]byte, error) {
	if len(ks) != 64 {
		return [32]byte{}, errors.New("public key is not 64 characters long")
	}
	bs, err := hex.DecodeString(ks)
	if err != nil {
		return [32]byte{}, err
	}
	if len(bs) != 32 {
		return [32]byte{}, errors.New("public key is not 32 bytes long")
	}
	var key [32]byte
	copy(key[:], bs)
	return key, nil
}
