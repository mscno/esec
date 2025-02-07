// Package crypto implements a simple convenience wrapper around
// golang.org/x/crypto/nacl/box. It ultimately models a situation where you
// don't care about authenticating the encryptor, so the nonce and encryption
// public key are prepended to the encrypted message.
//
// Shared key precomputation is used when encrypting but not when decrypting.
// This is not an inherent limitation, but it would complicate the
// implementation a little bit to do precomputation during decryption also.
// If performance becomes an issue (highly unlikely), it's completely feasible
// to add.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Keypair models a Curve25519 keypair. To generate a new Keypair, declare an
// empty one and call Generate() on it.
type Keypair struct {
	Public  [32]byte
	Private [32]byte
}

// Encrypter is generated from a keypair (typically a newly-generated ephemeral
// keypair, used only for this session) with the public key of an authorized
// decrypter. It is then capable of encrypting messages to that decrypter's
// private key. An instance should normally be obtained only by calling
// Encrypter() on a Keypair instance.
type Encrypter struct {
	Keypair    *Keypair
	PeerPublic [32]byte
	SharedKey  [32]byte
}

// Decrypter is generated from a keypair (a fixed keypair, generally, whose
// private key is stored in configuration management or otherwise), and used to
// decrypt messages. It should normally be obtained by calling Decrypter() on a
// Keypair instance.
type Decrypter struct {
	Keypair *Keypair
}

// ErrDecryptionFailed means the decryption didn't work. This normally
// indicates that the message was corrupted or the wrong keypair was used.
var ErrDecryptionFailed = errors.New("couldn't decrypt message")

// Generate generates a new Curve25519 keypair into a (presumably) empty Keypair
// structure.
func (k *Keypair) Generate() (err error) {
	var pub, priv *[32]byte
	pub, priv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	k.Public = *pub
	k.Private = *priv
	return
}

// PublicString returns the public key in the canonical hex-encoded printable form.
func (k *Keypair) PublicString() string {
	return fmt.Sprintf("%x", k.Public)
}

// PrivateString returns the private key in the canonical hex-encoded printable form.
func (k *Keypair) PrivateString() string {
	return fmt.Sprintf("%x", k.Private)
}

// Encrypter returns an Encrypter instance, given a public key, to encrypt
// messages to the paired, unknown, private key.
func (k *Keypair) Encrypter(peerPublic [32]byte) *Encrypter {
	return NewEncrypter(k, peerPublic)
}

// Decrypter returns a Decrypter instance, used to decrypt properly formatted
// messages from arbitrary encrypters.
func (k *Keypair) Decrypter() *Decrypter {
	return &Decrypter{Keypair: k}
}

// NewEncrypter instantiates an Encrypter after pre-computing the shared key for
// the owned keypair and the given decrypter public key.
func NewEncrypter(kp *Keypair, peerPublic [32]byte) *Encrypter {
	var shared [32]byte
	box.Precompute(&shared, &peerPublic, &kp.Private)
	return &Encrypter{
		Keypair:    kp,
		PeerPublic: peerPublic,
		SharedKey:  shared,
	}
}

// Encrypt takes a plaintext message and returns an encrypted message. Unlike
// raw nacl/box encryption, this message is decryptable without passing the
// nonce or public key out-of-band, as it includes both. This is not less
// secure, it just doesn't allow for authorizing the encryptor. That's fine,
// since authorization isn't a desired property of this particular cryptosystem.
func (e *Encrypter) Encrypt(message []byte) ([]byte, error) {
	if IsBoxedMessage(message) {
		return message, nil
	}
	boxedMessage, err := e.encrypt(message)
	if err != nil {
		return nil, err
	}
	return boxedMessage.Dump(), nil
}

func (e *Encrypter) encrypt(message []byte) (*boxedMessage, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	out := box.SealAfterPrecomputation(nil, message, &nonce, &e.SharedKey)

	return &boxedMessage{
		SchemaVersion:   1,
		EncrypterPublic: e.Keypair.Public,
		Nonce:           nonce,
		Box:             out,
	}, nil
}

// Decrypt is passed an encrypted message or a particular format (the format
// generated by (*Encrypter)Encrypt(), which includes the nonce and public key
// used to create the ciphertext. It returns the decrypted string. Note that,
// unlike with encryption, Shared-key-precomputation is not used for decryption.
func (d *Decrypter) Decrypt(message []byte) ([]byte, error) {
	var bm boxedMessage
	if err := bm.Load(message); err != nil {
		return nil, err
	}
	return d.decrypt(&bm)
}

func (d *Decrypter) decrypt(bm *boxedMessage) ([]byte, error) {
	//fmt.Printf("Decrypting message with nonce %x\n", bm.Nonce)
	//fmt.Printf("Encrypter public key: %x\n", bm.EncrypterPublic)
	//fmt.Printf("Decrypter public key: %x\n", d.Keypair.Public)
	//fmt.Printf("Decrypter private key: %x\n", d.Keypair.Private)
	plaintext, ok := box.Open(nil, bm.Box, &bm.Nonce, &bm.EncrypterPublic, &d.Keypair.Private)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func genNonce() (nonce [24]byte, err error) {
	var n int
	n, err = rand.Read(nonce[0:24])
	if err != nil {
		return
	}
	if n != 24 {
		err = fmt.Errorf("not enough bytes returned from rand.Reader")
	}
	return
}

// ErrInvalidKeyFormat means the key was not in the expected format.
var ErrInvalidKeyFormat = fmt.Errorf("invalid key format")
