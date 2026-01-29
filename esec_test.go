package esec

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/testdata"
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
		_, err := Encrypt(bytes.NewBufferString(`{"a": "b"]`), bytes.NewBuffer(nil), FileFormatEjson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "invalid character") {
			t.Errorf("wanted json error, but got %v", err)
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		// invalid key
		_, err := Encrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "invalid"}`), bytes.NewBuffer(nil), FileFormatEjson)
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "public key has invalid format") {
			t.Errorf("wanted key error, but got %v", err)
		}
	})

	t.Run("valid keypair", func(t *testing.T) {
		// valid keypair
		var output bytes.Buffer
		_, err := Encrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`), &output, FileFormatEjson)
		assertNoError(t, err)
		match := regexp.MustCompile(`{"_ESEC_PUBLIC_KEY": "8d8.*", "a": "ESEC.*"}`)
		if match.Find(output.Bytes()) == nil {
			t.Errorf("unexpected output: %s", output.String())
		}
	})
}

func TestDecryptDotEnvFile(t *testing.T) {
	t.Run("valid keypair", func(t *testing.T) {
		// valid keypair and a corresponding entry in keydir
		var out bytes.Buffer
		_, err := Decrypt(
			bytes.NewBuffer([]byte(`
ESEC_PUBLIC_KEY=39e66b09af00d7cce70ef8f41a0f54e652c392e5a34be2702050c9c184a70557

SECRET=ESEC[1:3IbHlK9p1dX8B3dYc3pyl4KmkSHHqCN4jy3TpwCAQww=:7grw6wdWI9yQrd9Sdy1xwS8gNove91JU:WXOFjTE+FGQ8Y8S2ogiIxjKZiAsfZ3H+NkqW]
`)),
			&out,
			"",
			FileFormatEnv,
			"",
			"2894bbe7b4e57ffdce8be56ff3cb25341360473d771ce250ba96bb56b307f933")
		assertNoError(t, err)
		s := out.String()
		v := `
ESEC_PUBLIC_KEY=39e66b09af00d7cce70ef8f41a0f54e652c392e5a34be2702050c9c184a70557

SECRET="my_secret"
`
		if s != v {
			t.Errorf("unexpected output: %s", s)
		}
	})
}

func TestDecryptFile(t *testing.T) {
	t.Run("invalid json file", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBufferString(`{"a": "b"]`), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
		if err == nil {
			t.Errorf("expected error, but none was received")
		} else if !strings.Contains(err.Error(), "invalid character") {
			t.Errorf("wanted json error, but got %v", err)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		// invalid json file
		_, err := Decrypt(bytes.NewBufferString(`{"_missing": "invalid"}`), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "invalid"}`), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`), bytes.NewBuffer(nil), "", FileFormatEjson, "", "c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87")
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
		_, err := Decrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`), bytes.NewBuffer(nil), "", FileFormatEjson, "/tmp", "")
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
		_, err := Decrypt(bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`), bytes.NewBuffer(nil), "", FileFormatEjson, "", "586518639ad138d6c0ce76ce6fc30f54a40e3c5e066b93f0151cebe0ee6ea391")
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
			bytes.NewBufferString(`{"_ESEC_PUBLIC_KEY": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "ESEC[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`),
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
			wantErr: true,
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
			gotEnv, err := sniffEnvName(slog.Default())

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

// Import the test embedded files from testdata package
var testFS = testdata.TestEmbed

func TestDecryptFromEmbedFS(t *testing.T) {
	// Set up environment variables for testing
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

	// Test with config-based API
	t.Run("using config with explicit env name", func(t *testing.T) {
		// Create test configuration with explicit environment
		config := DecryptFromEmbedConfig{
			EnvName: "",
			Format:  FileFormatEjson,
			Logger:  slog.New(slog.NewTextHandler(ioutil.Discard, nil)),
		}

		// Set up private key in environment
		os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")

		// Call the function under test
		_, err := DecryptFromEmbedFSWithConfig(testFS, config)
		assert.NoError(t, err)
	})

	t.Run("using config with custom environment lookuper", func(t *testing.T) {
		// Create a custom lookuper that always returns "test"
		customLookuper := func() (string, error) {
			return "test", nil
		}

		// Create test configuration with custom lookuper
		config := DecryptFromEmbedConfig{
			Format:              FileFormatEjson,
			Logger:              slog.New(slog.NewTextHandler(ioutil.Discard, nil)),
			EnvironmentLookuper: customLookuper,
		}

		// Set up private key for "test" environment in environment variables
		os.Setenv("ESEC_PRIVATE_KEY_TEST", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")

		// Call the function under test (this should use the custom lookuper)
		_, err := DecryptFromEmbedFSWithConfig(testFS, config)
		// This will fail because our test.ejson file doesn't have a test.ejson variant
		// but that's expected - we're just checking the lookuper gets called
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "error reading file from vault"))
	})

	t.Run("using combined lookupers with fallback", func(t *testing.T) {
		// Create a failing lookuper and a successful fallback
		failingLookuper := func() (string, error) {
			return "", fmt.Errorf("this lookuper always fails")
		}

		successLookuper := func() (string, error) {
			return "", nil // Default environment
		}

		// Create test configuration with multiple lookupers
		config := DecryptFromEmbedConfig{
			Format:              FileFormatEjson,
			Logger:              slog.New(slog.NewTextHandler(ioutil.Discard, nil)),
			EnvironmentLookuper: CombineLookupers(failingLookuper, successLookuper),
		}

		// Set up private key in environment
		os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")

		// Call the function under test
		_, err := DecryptFromEmbedFSWithConfig(testFS, config)
		assert.NoError(t, err)
	})

	// Test for backward compatibility
	t.Run("using legacy options API", func(t *testing.T) {
		// Clear environment variables to prevent multiple key issues
		os.Clearenv()
		// Set up private key in environment
		os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")

		// Call the legacy function
		_, err := DecryptFromEmbedFSWithOptions(testFS, WithFormat(FileFormatEjson))
		assert.NoError(t, err)
	})
}

func TestCombineLookupers(t *testing.T) {
	t.Run("all lookupers fail", func(t *testing.T) {
		lookuper1 := func() (string, error) {
			return "", fmt.Errorf("error 1")
		}
		lookuper2 := func() (string, error) {
			return "", fmt.Errorf("error 2")
		}

		combined := CombineLookupers(lookuper1, lookuper2)
		env, err := combined()

		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "error 1"))
		assert.True(t, strings.Contains(err.Error(), "error 2"))
		assert.Equal(t, "", env)
	})

	t.Run("first lookuper succeeds", func(t *testing.T) {
		lookuper1 := func() (string, error) {
			return "env1", nil
		}
		lookuper2 := func() (string, error) {
			return "env2", nil
		}

		combined := CombineLookupers(lookuper1, lookuper2)
		env, err := combined()

		assert.NoError(t, err)
		assert.Equal(t, "env1", env)
	})

	t.Run("second lookuper succeeds after first fails", func(t *testing.T) {
		lookuper1 := func() (string, error) {
			return "", fmt.Errorf("error 1")
		}
		lookuper2 := func() (string, error) {
			return "env2", nil
		}

		combined := CombineLookupers(lookuper1, lookuper2)
		env, err := combined()

		assert.NoError(t, err)
		assert.Equal(t, "env2", env)
	})

	t.Run("no lookupers provided", func(t *testing.T) {
		combined := CombineLookupers()
		env, err := combined()

		assert.Error(t, err)
		assert.Equal(t, "", env)
		assert.True(t, strings.Contains(err.Error(), "no environment lookupers were provided"))
	})
}

func TestSniffFromKeyring(t *testing.T) {
	// Setup a logger that doesn't output anything for tests
	logger := slog.New(slog.NewTextHandler(ioutil.Discard, nil))

	// Helper to create a temporary directory with a keyring file
	setupKeyring := func(t *testing.T, content string) string {
		t.Helper()
		dir, err := ioutil.TempDir("", "esec-test-")
		assert.NoError(t, err)

		// Register cleanup function
		t.Cleanup(func() {
			os.RemoveAll(dir)
		})

		// Write the keyring file
		keyringPath := filepath.Join(dir, ".esec-keyring")
		err = ioutil.WriteFile(keyringPath, []byte(content), 0600)
		assert.NoError(t, err)

		return dir
	}

	t.Run("Returns provided envName when not empty", func(t *testing.T) {
		// Setup an empty keyring
		dir := setupKeyring(t, "")

		// Call the function with a non-empty envName
		result, err := sniffFromKeyring(logger, dir, "test-env")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "test-env", result)
	})

	t.Run("Error when keyring file doesn't exist", func(t *testing.T) {
		// Use a temporary directory without creating a keyring file
		dir, err := ioutil.TempDir("", "esec-test-")
		assert.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })

		// Call the function
		_, err = sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "keyring file does not exist"))
	})

	t.Run("Error when keyring file can't be parsed", func(t *testing.T) {
		// Setup an invalid keyring file
		dir := setupKeyring(t, "this is not a valid .env file format===")

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "no environment keys found in keyring"))
	})

	t.Run("Error when both ACTIVE_KEY and ACTIVE_ENVIRONMENT are set", func(t *testing.T) {
		// Setup a conflicting keyring
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=ESEC_PRIVATE_KEY_PROD
ESEC_ACTIVE_ENVIRONMENT=dev
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "conflicting configuration"))
	})

	t.Run("Successfully using ACTIVE_ENVIRONMENT", func(t *testing.T) {
		// Setup a keyring with ACTIVE_ENVIRONMENT
		dir := setupKeyring(t, `
ESEC_ACTIVE_ENVIRONMENT=prod
ESEC_PRIVATE_KEY_PROD=somekey
ESEC_PRIVATE_KEY_DEV=anotherkey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "prod", result)
	})

	t.Run("Error when ACTIVE_ENVIRONMENT is empty", func(t *testing.T) {
		// Setup a keyring with empty ACTIVE_ENVIRONMENT
		dir := setupKeyring(t, `
ESEC_ACTIVE_ENVIRONMENT=
ESEC_PRIVATE_KEY_PROD=somekey
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "is set but empty"))
	})

	t.Run("Successfully using ACTIVE_KEY with default key", func(t *testing.T) {
		// Setup a keyring with ACTIVE_KEY pointing to default key
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=ESEC_PRIVATE_KEY
ESEC_PRIVATE_KEY=somekey
ESEC_PRIVATE_KEY_PROD=anotherkey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "", result, "Should return empty string for default environment")
	})

	t.Run("Successfully using ACTIVE_KEY with environment key", func(t *testing.T) {
		// Setup a keyring with ACTIVE_KEY pointing to an environment key
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=ESEC_PRIVATE_KEY_STAGING
ESEC_PRIVATE_KEY=somekey
ESEC_PRIVATE_KEY_STAGING=anotherkey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "staging", result)
	})

	t.Run("Successfully using ACTIVE_KEY with environment key containing underscores", func(t *testing.T) {
		// Setup a keyring with ACTIVE_KEY pointing to a key with underscores
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=ESEC_PRIVATE_KEY___TEST_ENV
ESEC_PRIVATE_KEY___TEST_ENV=somekey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "test_env", result)
	})

	t.Run("Error when ACTIVE_KEY has invalid format", func(t *testing.T) {
		// Setup a keyring with ACTIVE_KEY with invalid format
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=INVALID_KEY_FORMAT
ESEC_PRIVATE_KEY=somekey
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "must be an ESEC_PRIVATE_KEY"))
	})

	t.Run("Error when ACTIVE_KEY has empty environment suffix", func(t *testing.T) {
		// Setup a keyring with ACTIVE_KEY with empty suffix
		dir := setupKeyring(t, `
ESEC_ACTIVE_KEY=ESEC_PRIVATE_KEY_
ESEC_PRIVATE_KEY_=somekey
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "could not extract environment"))
	})

	t.Run("Fallback to single environment key", func(t *testing.T) {
		// Setup a keyring with a single environment key
		dir := setupKeyring(t, `
ESEC_PRIVATE_KEY_QA=somekey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "qa", result)
	})

	t.Run("Error with multiple environment keys and no active indicators", func(t *testing.T) {
		// Setup a keyring with multiple environment keys but no active indicators
		dir := setupKeyring(t, `
ESEC_PRIVATE_KEY_DEV=somekey
ESEC_PRIVATE_KEY_PROD=anotherkey
ESEC_PRIVATE_KEY_QA=yetanotherkey
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "multiple environment keys found"))
	})

	t.Run("Successfully using default environment with ESEC_PRIVATE_KEY", func(t *testing.T) {
		// Setup a keyring with only the default key
		dir := setupKeyring(t, `
ESEC_PRIVATE_KEY=somekey
`)

		// Call the function
		result, err := sniffFromKeyring(logger, dir, "")

		// Verify the result
		assert.NoError(t, err)
		assert.Equal(t, "", result, "Should return empty string for default environment")
	})

	t.Run("Error when no keys found", func(t *testing.T) {
		// Setup an empty keyring
		dir := setupKeyring(t, `
SOME_OTHER_KEY=value
`)

		// Call the function
		_, err := sniffFromKeyring(logger, dir, "")

		// Verify we get an error
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "no environment keys found"))
	})
}

// Helper function to split an environment variable string (KEY=VALUE)
func splitEnvVar(envVar string) []string {
	return strings.SplitN(envVar, "=", 2)
}

// Helper function to check if an error message contains a prefix
func containsPrefix(errMsg, prefix string) bool {
	return len(errMsg) >= len(prefix) && errMsg[:len(prefix)] == prefix
}
