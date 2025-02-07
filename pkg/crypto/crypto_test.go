package crypto

import (
	"fmt"
	"github.com/alecthomas/assert/v2"
	"testing"
)

func TestKeypairGeneration(t *testing.T) {
	var kp Keypair

	t.Run("Generating keypairs", func(t *testing.T) {
		err := kp.Generate()
		assert.NoError(t, err)

		t.Run("should generate something that looks vaguely key-like", func(t *testing.T) {
			assert.NotEqual(t, kp.PublicString(), kp.PrivateString())
			assert.NotContains(t, kp.PublicString(), "00000")
			assert.NotContains(t, kp.PrivateString(), "00000")
		})

		t.Run("should not leave the keys zeroed", func(t *testing.T) {
			pubIsNull := kp.Public[0] == 0 && kp.Public[1] == 0 && kp.Public[2] == 0
			privIsNull := kp.Private[0] == 0 && kp.Private[1] == 0 && kp.Private[2] == 0
			assert.False(t, pubIsNull)
			assert.False(t, privIsNull)
		})
	})
}

func TestNonceGeneration(t *testing.T) {
	t.Run("Generating a nonce", func(t *testing.T) {
		t.Run("should be unique", func(t *testing.T) {
			n1, _ := genNonce()
			n2, _ := genNonce()
			assert.NotEqual(t, n1, n2)
		})

		t.Run("should complete successfully", func(t *testing.T) {
			n, err := genNonce()
			assert.NoError(t, err)
			assert.NotContains(t, fmt.Sprintf("%x", n), "00000")
		})
	})
}

func TestRoundtrip(t *testing.T) {
	var kpEphemeral, kpSecret Keypair
	err := kpEphemeral.Generate()
	assert.NoError(t, err)
	err = kpSecret.Generate()
	assert.NoError(t, err)

	t.Run("Roundtripping", func(t *testing.T) {
		encrypter := kpEphemeral.Encrypter(kpSecret.Public)
		decrypter := kpSecret.Decrypter()
		message := []byte("This is a test of the emergency broadcast system.")

		ct, err := encrypter.Encrypt(message)
		assert.NoError(t, err)

		ct2, err := encrypter.Encrypt(ct) // this one will leave the message unchanged
		assert.NoError(t, err)
		assert.Equal(t, ct2, ct)

		pt, err := decrypter.Decrypt(ct2)
		assert.NoError(t, err)
		assert.Equal(t, pt, message)
		assert.NotEqual(t, pt, ct)
		assert.True(t, len(ct) > len(pt))
	})
}

/*
func exampleEncrypt(peerPublic [32]byte) {
	var kp Keypair
	if err := kp.Generate(); err != nil {
		panic(err)
	}

	encrypter := kp.Encrypter(peerPublic)
	boxed, err := encrypter.Encrypt([]byte("this is my message"))
	fmt.Println(boxed, err)
}

func exampleDecrypt(myPublic, myPrivate [32]byte, encrypted []byte) {
	kp := Keypair{
		Public:  myPublic,
		Private: myPrivate,
	}

	decrypter := kp.Decrypter()
	plaintext, err := decrypter.Decrypt(encrypted)
	fmt.Println(plaintext, err)
}
*/
