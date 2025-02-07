package esec

import (
	"bytes"
	"github.com/alecthomas/assert/v2"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	assertNoError(t, err)
	if pub == priv {
		t.Errorf("pub == priv")
	}
	if strings.Contains(pub, "00000") {
		t.Errorf("pubkey looks sketchy")
	}
	if strings.Contains(priv, "00000") {
		t.Errorf("privkey looks sketchy")
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEncryptFileInPlace(t *testing.T) {
	t.Run("invalid json file", func(t *testing.T) {
		n, err := EncryptFileInPlace("testdata/.ejson")
		assert.NoError(t, err)
		assert.Equal(t, 666, n)
	})

}

func TestEncrypt(t *testing.T) {
	t.Run("invalid json file", func(t *testing.T) {
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"a": "b"]`)), bytes.NewBuffer(nil), Ejson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "invalid character") {
				t.Errorf("wanted json error, but got %v", err)
			}
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		// invalid key
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "invalid"}`)), bytes.NewBuffer(nil), Ejson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "public key has invalid format") {
				t.Errorf("wanted key error, but got %v", err)
			}
		}
	})

	t.Run("valid keypair", func(t *testing.T) {
		// valid keypair
		var output bytes.Buffer
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)), &output, Ejson)
		assertNoError(t, err)
		match := regexp.MustCompile(`{"_ESEC_PUBLIC_KEY": "8d8.*", "a": "ESEC.*"}`)
		if match.Find(output.Bytes()) == nil {
			t.Errorf("unexpected output: %s", output.String())
		}
	})
}

func TestDecryptFile(t *testing.T) {

	t.Run("invalid json file", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"a": "b"]`)), bytes.NewBuffer(nil), "", Ejson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "invalid character") {
				t.Errorf("wanted json error, but got %v", err)
			}
		}
	})

	t.Run("missing key", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_missing": "invalid"}`)), bytes.NewBuffer(nil), "", Ejson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "public key not present in ecfg file") {
				t.Errorf("wanted missing key error, but got %v", err)
			}
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "invalid"}`)), bytes.NewBuffer(nil), "", Ejson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "public key has invalid format") {
				t.Errorf("wanted key error, but got %v", err)
			}
		}
	})

	t.Run("invalid file and invalid message format", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)), bytes.NewBuffer(nil), "", Ejson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "invalid message format") {
				t.Errorf("wanted key error, but got %v", err)
			}
		}
	})

	t.Run("valid file, but invalid keypath", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`)), bytes.NewBuffer(nil), "", Ejson, "/tmp", "")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "private key \"ESEC_PRIVATE_KEY\" not found in environment variables, and keyring file does not exist at \"/tmp/.esec-keyring\"") {
				t.Errorf("wanted key error, but got %v", err)
			}
		}
	})

	t.Run("valid file, but invalid userkey", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`)), bytes.NewBuffer(nil), "", Ejson, "", "586518639ad138d6c0ce76ce6fc30f54a40e3c5e066b93f0151cebe0ee6ea391")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else {
			if !strings.Contains(err.Error(), "couldn't decrypt message") {
				t.Errorf("wanted key error, but got %v", err)
			}
		}
	})

	t.Run("valid keypair", func(t *testing.T) {
		// valid keypair and a corresponding entry in keydir
		var out bytes.Buffer
		_, err := Decrypt(
			bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`)),
			&out,
			"",
			Ejson,
			"",
			"c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		assertNoError(t, err)
		s := out.String()
		if s != `{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}` {
			t.Errorf("unexpected output: %s", s)
		}
	})

}
