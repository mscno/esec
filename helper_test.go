package esec

import (
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
			gotFilename, gotEnv, err := processFileOrEnv(tt.input)

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
