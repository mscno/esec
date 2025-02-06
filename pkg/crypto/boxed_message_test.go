package crypto

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestBoxedMessageRoundtripping(t *testing.T) {
	pk := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	nonce := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	wire := "ESEC[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"

	t.Run("Dump", func(t *testing.T) {
		bm := boxedMessage{
			SchemaVersion:   1,
			EncrypterPublic: pk,
			Nonce:           nonce,
			Box:             []byte{3, 3, 3},
		}
		assert.Equal(t, wire, string(bm.Dump()))
	})

	t.Run("Load", func(t *testing.T) {
		bm := boxedMessage{}
		err := bm.Load([]byte(wire))
		assert.NoError(t, err)
		assert.Equal(t, pk, bm.EncrypterPublic)
		assert.Equal(t, nonce, bm.Nonce)
		assert.Equal(t, []byte{3, 3, 3}, bm.Box)
	})

	t.Run("IsBoxedMessage", func(t *testing.T) {
		assert.True(t, IsBoxedMessage([]byte(wire)))
		assert.False(t, IsBoxedMessage([]byte("nope")))
		assert.False(t, IsBoxedMessage([]byte("ESEC[]")))
		assert.True(t, IsBoxedMessage([]byte("ESEC[1:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a]")))
	})
}
