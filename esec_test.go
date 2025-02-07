package esec

import (
	"bytes"
	"github.com/alecthomas/assert/v2"
	"os"
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
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"a": "b"]`)), bytes.NewBuffer(nil), FileFormatEjson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "invalid character") {
			t.Errorf("wanted json error, but got %v", err)
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		// invalid key
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "invalid"}`)), bytes.NewBuffer(nil), FileFormatEjson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "public key has invalid format") {
			t.Errorf("wanted key error, but got %v", err)
		}
	})

	t.Run("valid keypair", func(t *testing.T) {
		// valid keypair
		var output bytes.Buffer
		_, err := Encrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)), &output, FileFormatEjson)
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
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"a": "b"]`)), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "invalid character") {
			t.Errorf("wanted json error, but got %v", err)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_missing": "invalid"}`)), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "invalid"}`)), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`)), bytes.NewBuffer(nil), "", FileFormatEjson, "/tmp", "")
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
		_, err := Decrypt(bytes.NewBuffer([]byte(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`)), bytes.NewBuffer(nil), "", FileFormatEjson, "", "586518639ad138d6c0ce76ce6fc30f54a40e3c5e066b93f0151cebe0ee6ea391")
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
			FileFormatEjson,
			"",
			"c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		assertNoError(t, err)
		s := out.String()
		if s != `{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}` {
			t.Errorf("unexpected output: %s", s)
		}
	})
}

func TestSniffEnvName(t *testing.T) {
	tests := []struct {
		name          string
		envVars       map[string]string
		wantEnv       string
		wantErr       bool
		wantErrPrefix string
	}{
		{
			name:    "No environment variables set",
			envVars: map[string]string{},
			wantEnv: "",
			wantErr: false,
		},
		{
			name:    "Only ESEC_PRIVATE_KEY set",
			envVars: map[string]string{"ESEC_PRIVATE_KEY": "somevalue"},
			wantEnv: "",
			wantErr: false,
		},
		{
			name:    "One valid ESEC_PRIVATE_KEY with environment",
			envVars: map[string]string{"ESEC_PRIVATE_KEY_PROD": "somevalue"},
			wantEnv: "prod",
			wantErr: false,
		},
		{
			name:    "One valid ESEC_PRIVATE_KEY with uppercase environment",
			envVars: map[string]string{"ESEC_PRIVATE_KEY_STAGING": "somevalue"},
			wantEnv: "staging", // Should return lowercase
			wantErr: false,
		},
		{
			name: "Multiple private keys found",
			envVars: map[string]string{
				"ESEC_PRIVATE_KEY_PROD":    "somevalue",
				"ESEC_PRIVATE_KEY_DEV":     "somevalue",
				"ESEC_PRIVATE_KEY_STAGING": "somevalue",
			},
			wantErr:       true,
			wantErrPrefix: "multiple private keys found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Backup original environment
			originalEnv := os.Environ()
			defer func() {
				os.Clearenv()
				for _, e := range originalEnv {
					parts := splitEnvVar(e)
					if len(parts) == 2 {
						os.Setenv(parts[0], parts[1])
					}
				}
			}()

			// Set up test environment variables
			os.Clearenv()
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Run SniffEnvName()
			gotEnv, err := sniffEnvName()

			// Check error case
			if tt.wantErr {
				if err == nil {
					t.Errorf("SniffEnvName() error = nil, want error with prefix %v", tt.wantErrPrefix)
					return
				}
				if !containsPrefix(err.Error(), tt.wantErrPrefix) {
					t.Errorf("SniffEnvName() error = %v, want error with prefix %v", err, tt.wantErrPrefix)
				}
				return
			}

			// Check non-error case
			if err != nil {
				t.Errorf("SniffEnvName() unexpected error = %v", err)
				return
			}

			if gotEnv != tt.wantEnv {
				t.Errorf("SniffEnvName() = %v, want %v", gotEnv, tt.wantEnv)
			}
		})
	}
}

// Helper function to split an environment variable string (KEY=VALUE)
func splitEnvVar(envVar string) []string {
	return strings.SplitN(envVar, "=", 2)
}

// Helper function to check if an error message contains a prefix
func containsPrefix(errMsg, prefix string) bool {
	return len(errMsg) >= len(prefix) && errMsg[:len(prefix)] == prefix
}
