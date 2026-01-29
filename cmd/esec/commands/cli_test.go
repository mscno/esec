package commands

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/pkg/fileutils"
)

func TestKeygenCmd(t *testing.T) {
	cmd := &KeygenCmd{}

	// Capture CLI output
	out, err := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Ensure no errors
	assert.Equal(t, err, "")

	// Validate output contains keys
	assert.Contains(t, out, "Public Key:")
	assert.Contains(t, out, "Private Key:")
}

func TestEncryptCmd(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), ".ejson")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test

	// Write test data
	_, err = tmpFile.WriteString(`{"ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "test123"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &EncryptCmd{File: tmpFile.Name(), Format: ".ejson"}

	// Run command
	out, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "Encrypted 347 bytes\n")
}

func TestEncryptCmdBadFile(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), ".ejson")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test

	// Write test data
	_, err = tmpFile.WriteString(`{"secret": "test123"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &EncryptCmd{File: tmpFile.Name(), Format: ".ejson"}

	// Run command
	out, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Contains(t, errString, "public key not present in ecfg file")
	assert.Equal(t, out, "")
}

func TestDecryptCmd(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), ".ejson")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	// Write test data
	_, err = tmpFile.WriteString(`{"_ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &DecryptCmd{File: tmpFile.Name(), Format: ".ejson"}

	// Run command
	out, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "{\"_ESEC_PUBLIC_KEY\":\"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d\",\"secret\": \"hello\"}\n")
}

func TestGetCmdOk(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), ".ejson")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	// Write test data
	_, err = tmpFile.WriteString(`{"_ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &GetCmd{File: tmpFile.Name(), Key: "secret", Format: ".ejson"}

	// Run command
	out, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "hello")
}

func TestGetCmdOkWithEnv(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.Create(path.Join(os.TempDir(), ".ejson.production"))
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test
	os.Setenv("ESEC_PRIVATE_KEY_PRODUCTION", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	// Write test data
	_, err = tmpFile.WriteString(`{"_ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &GetCmd{File: tmpFile.Name(), Key: "secret", Format: ".ejson"}

	// Run command
	out, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Equal(t, errString, "")
	assert.Equal(t, out, "hello")
}

func TestGetCmdMissing(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), ".ejson")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test
	os.Setenv("ESEC_PRIVATE_KEY", "24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5")
	// Write test data
	_, err = tmpFile.WriteString(`{"_ESEC_PUBLIC_KEY":"493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d","secret": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]"}`)
	assert.NoError(t, err)
	tmpFile.Close()

	// Create command
	cmd := &GetCmd{File: tmpFile.Name(), Key: "missing", Format: ".ejson"}

	// Run command
	_, errString := captureOutput(func() error {
		return cmd.Run(&cliCtx{Logger: slog.Default()})
	})

	// Check expected output
	assert.Equal(t, errString, `key "missing" not found in decrypted content`)
}

func TestProcessFileOrEnv(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantFilename  string
		wantEnv       string
		wantErr       bool
		wantErrPrefix string // partial error message to check
	}{
		{
			name:         "simple env file",
			input:        ".env",
			wantFilename: ".env",
			wantEnv:      "",
			wantErr:      false,
		},
		{
			name:         "env file with environment",
			input:        ".env.prod",
			wantFilename: ".env.prod",
			wantEnv:      "prod",
			wantErr:      false,
		},
		{
			name:         "ejson file with environment",
			input:        ".ejson.staging",
			wantFilename: ".ejson.staging",
			wantEnv:      "staging",
			wantErr:      false,
		},
		{
			name:         "env string prod",
			input:        ".env.prod",
			wantFilename: ".env.prod",
			wantEnv:      "prod",
			wantErr:      false,
		},
		{
			name:         "env string staging",
			input:        ".env.staging",
			wantFilename: ".env.staging",
			wantEnv:      "staging",
			wantErr:      false,
		},
		{
			name:         "env string dev",
			input:        "dev",
			wantFilename: ".ejson.dev",
			wantEnv:      "dev",
			wantErr:      false,
		},
		{
			name:         "blank string",
			input:        "",
			wantFilename: ".ejson",
			wantEnv:      "",
			wantErr:      false,
		},
		{
			name:          "invalid file prefix",
			input:         ".invalid",
			wantErr:       true,
			wantErrPrefix: "invalid environment name: .invalid - should not contain dots or path separators",
		},
		{
			name:          "uppercase environment",
			input:         "PROD",
			wantErr:       true,
			wantErrPrefix: "invalid environment name",
		},
		{
			name:          "environment with dot",
			input:         "prod.test",
			wantErr:       true,
			wantErrPrefix: "invalid environment name",
		},
		{
			name:          "environment with slash",
			input:         "prod/test",
			wantErr:       true,
			wantErrPrefix: "invalid environment name: prod/test - should not contain dots or path separators",
		},
		{
			name:         "environment with slash",
			input:        "prod/.ejson",
			wantErr:      false,
			wantFilename: "prod/.ejson",
			wantEnv:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFilename, err := processFileOrEnv(tt.input, fileutils.Ejson)

			// Check error cases
			if tt.wantErr {
				if err == nil {
					t.Errorf("ProcessFileOrEnv() error = nil, want error with prefix %v", tt.wantErrPrefix)
					return
				}
				if !strings.HasPrefix(err.Error(), tt.wantErrPrefix) {
					t.Errorf("ProcessFileOrEnv() error = %v, want error with prefix %v", err, tt.wantErrPrefix)
				}
				return
			}

			// Check non-error cases
			if err != nil {
				t.Errorf("ProcessFileOrEnv() unexpected error = %v", err)
				return
			}

			if gotFilename != tt.wantFilename {
				t.Errorf("ProcessFileOrEnv() filename = %v, want %v", gotFilename, tt.wantFilename)
			}

			// if gotEnv != tt.wantEnv {
			//	t.Errorf("ProcessFileOrEnv() env = %v, want %v", gotEnv, tt.wantEnv)
			//}
		})
	}
}

// Helper function to capture CLI output
func captureOutput(f func() error) (string, string) {
	// Save original stdout and stderr
	oldOut := os.Stdout
	oldErr := os.Stderr

	// Create new pipes to capture output
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	// Run function while capturing output
	err := f()
	if err != nil {
		return "", err.Error()
	}
	// Close writers
	wOut.Close()
	wErr.Close()

	// Read output from pipes
	var outBuf, errBuf bytes.Buffer
	io.Copy(&outBuf, rOut)
	io.Copy(&errBuf, rErr)

	// Restore original stdout and stderr
	os.Stdout = oldOut
	os.Stderr = oldErr

	return outBuf.String(), errBuf.String()
}
