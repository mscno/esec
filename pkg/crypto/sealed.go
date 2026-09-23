package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

// SealAnonymous encrypts message for the recipient's public key using a NaCl
// sealed box: an ephemeral keypair is generated for each call and its public
// half is prepended to the ciphertext, so the sender stays anonymous and no
// sender key management is needed.
func SealAnonymous(message []byte, recipientPublic *[32]byte) ([]byte, error) {
	return box.SealAnonymous(nil, message, recipientPublic, rand.Reader)
}

// OpenAnonymous decrypts a message produced by SealAnonymous using the
// recipient's keypair. It returns ErrDecryptionFailed if the message was
// corrupted or sealed for a different key.
func OpenAnonymous(boxed []byte, public, private *[32]byte) ([]byte, error) {
	out, ok := box.OpenAnonymous(nil, boxed, public, private)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return out, nil
}
