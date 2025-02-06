package format

import (
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	PublicKeyField            = "ESEC_PUBLIC_KEY"
	UnderscoredPublicKeyField = "_ESEC_PUBLIC_KEY"
)

type FormatHandler interface {
	TransformScalarValues([]byte, func([]byte) ([]byte, error)) ([]byte, error)
	ExtractPublicKey([]byte) ([32]byte, error)
}

// ErrPublicKeyMissing indicates that the PublicKeyField key was not found
// at the top level of the JSON document provided.
var ErrPublicKeyMissing = errors.New("public key not present in ecfg file")

// ErrPublicKeyInvalid means that the PublicKeyField key was found, but the
// value could not be parsed into a valid key.
var ErrPublicKeyInvalid = errors.New("public key has invalid format")

func ExtractPublicKeyHelper(obj map[string]interface{}) ([32]byte, error) {
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
