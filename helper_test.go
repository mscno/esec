package esec

import (
	"os"
	"strings"
	"testing"
)

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
			gotFilename, gotEnv, err := processFileOrEnv(tt.input, Ejson)

			// Check error cases
			if tt.wantErr {
				if err == nil {
					t.Errorf("processFileOrEnv() error = nil, want error with prefix %v", tt.wantErrPrefix)
					return
				}
				if !strings.HasPrefix(err.Error(), tt.wantErrPrefix) {
					t.Errorf("processFileOrEnv() error = %v, want error with prefix %v", err, tt.wantErrPrefix)
				}
				return
			}

			// Check non-error cases
			if err != nil {
				t.Errorf("processFileOrEnv() unexpected error = %v", err)
				return
			}

			if gotFilename != tt.wantFilename {
				t.Errorf("processFileOrEnv() filename = %v, want %v", gotFilename, tt.wantFilename)
			}

			if gotEnv != tt.wantEnv {
				t.Errorf("processFileOrEnv() env = %v, want %v", gotEnv, tt.wantEnv)
			}
		})
	}
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
			envVars: map[string]string{EsecPrivateKey: "somevalue"},
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

			// Run sniffEnvName()
			gotEnv, err := sniffEnvName()

			// Check error case
			if tt.wantErr {
				if err == nil {
					t.Errorf("sniffEnvName() error = nil, want error with prefix %v", tt.wantErrPrefix)
					return
				}
				if !containsPrefix(err.Error(), tt.wantErrPrefix) {
					t.Errorf("sniffEnvName() error = %v, want error with prefix %v", err, tt.wantErrPrefix)
				}
				return
			}

			// Check non-error case
			if err != nil {
				t.Errorf("sniffEnvName() unexpected error = %v", err)
				return
			}

			if gotEnv != tt.wantEnv {
				t.Errorf("sniffEnvName() = %v, want %v", gotEnv, tt.wantEnv)
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
