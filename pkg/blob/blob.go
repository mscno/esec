// Package blob encodes exact file bytes for storage inside an encrypted Esec
// string value. Encoding alone provides no confidentiality; callers must encrypt.
package blob

import (
	"encoding/base64"
	"errors"
	"strings"
)

// MaxSize bounds a decoded blob to 1 MiB.
const MaxSize = 1 << 20

const prefix = "esec-blob-v1:"

// Encode preserves arbitrary bytes, including empty files and trailing newlines.
func Encode(data []byte) (string, error) {
	if len(data) > MaxSize {
		return "", errors.New("blob exceeds the 1 MiB limit")
	}
	return prefix + base64.StdEncoding.EncodeToString(data), nil
}

// Decode accepts only a canonical v1 blob; ordinary secret values fail closed.
// Errors never include the value or any decoded content.
func Decode(value string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(value, prefix)
	if !ok || len(encoded) > base64.StdEncoding.EncodedLen(MaxSize) || strings.ContainsAny(encoded, "\r\n") {
		return nil, errors.New("invalid blob or unsupported blob version")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > MaxSize {
		clear(data)
		return nil, errors.New("invalid blob encoding or size")
	}
	return data, nil
}
