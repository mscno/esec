package commands

import (
	"runtime"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty command",
			command: []string{},
			wantErr: true,
			errMsg:  "no command specified",
		},
		{
			name:    "valid simple command",
			command: []string{"echo", "hello"},
			wantErr: false,
		},
		{
			name:    "valid command with flags",
			command: []string{"ls", "-la", "/tmp"},
			wantErr: false,
		},
		{
			name:    "command substitution with $()",
			command: []string{"echo", "$(whoami)"},
			wantErr: true,
			errMsg:  "shell metacharacters",
		},
		{
			name:    "command substitution with backticks",
			command: []string{"echo", "`whoami`"},
			wantErr: true,
			errMsg:  "shell metacharacters",
		},
		{
			name:    "nested command substitution",
			command: []string{"bash", "-c", "$(cat /etc/passwd)"},
			wantErr: true,
			errMsg:  "shell metacharacters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommand(tt.command)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateCommand() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("validateCommand() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateCommand() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestValidateCommandWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific tests skipped on non-Windows platform")
	}

	tests := []struct {
		name    string
		command []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "windows variable expansion",
			command: []string{"echo", "%PATH%"},
			wantErr: true,
			errMsg:  "Windows metacharacters",
		},
		{
			name:    "windows ampersand",
			command: []string{"cmd", "/c", "echo hello & echo world"},
			wantErr: true,
			errMsg:  "Windows metacharacter: &",
		},
		{
			name:    "windows pipe",
			command: []string{"cmd", "/c", "echo hello | more"},
			wantErr: true,
			errMsg:  "Windows metacharacter: |",
		},
		{
			name:    "windows caret (escape)",
			command: []string{"cmd", "/c", "echo ^hello"},
			wantErr: true,
			errMsg:  "Windows metacharacter: ^",
		},
		{
			name:    "windows redirection less than",
			command: []string{"cmd", "/c", "type < file.txt"},
			wantErr: true,
			errMsg:  "Windows metacharacter: <",
		},
		{
			name:    "windows redirection greater than",
			command: []string{"cmd", "/c", "echo hello > file.txt"},
			wantErr: true,
			errMsg:  "Windows metacharacter: >",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommand(tt.command)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateCommand() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("validateCommand() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateCommand() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestSanitizeEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "valid env vars unchanged",
			input: map[string]string{
				"FOO":        "bar",
				"DATABASE":   "postgres://localhost:5432",
				"API_KEY":    "secret123",
				"EMPTY":      "",
				"WITH_SPACE": "hello world",
			},
			expected: map[string]string{
				"FOO":        "bar",
				"DATABASE":   "postgres://localhost:5432",
				"API_KEY":    "secret123",
				"EMPTY":      "",
				"WITH_SPACE": "hello world",
			},
		},
		{
			name: "removes keys with equals sign",
			input: map[string]string{
				"VALID":   "value",
				"BAD=KEY": "should be removed",
			},
			expected: map[string]string{
				"VALID": "value",
			},
		},
		{
			name: "removes keys with semicolon",
			input: map[string]string{
				"VALID":   "value",
				"BAD;KEY": "should be removed",
			},
			expected: map[string]string{
				"VALID": "value",
			},
		},
		{
			name: "removes keys with newline",
			input: map[string]string{
				"VALID":    "value",
				"BAD\nKEY": "should be removed",
			},
			expected: map[string]string{
				"VALID": "value",
			},
		},
		{
			name: "mixed valid and invalid keys",
			input: map[string]string{
				"GOOD1":     "value1",
				"BAD=":      "bad1",
				"GOOD2":     "value2",
				"BAD;":      "bad2",
				"GOOD3":     "value3",
				"BAD\n":     "bad3",
				"ALSO_GOOD": "value4",
			},
			expected: map[string]string{
				"GOOD1":     "value1",
				"GOOD2":     "value2",
				"GOOD3":     "value3",
				"ALSO_GOOD": "value4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeEnvVars(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("sanitizeEnvVars() = %v, want nil", result)
				}
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("sanitizeEnvVars() returned %d items, want %d", len(result), len(tt.expected))
			}

			for k, v := range tt.expected {
				if got, ok := result[k]; !ok {
					t.Errorf("sanitizeEnvVars() missing expected key %q", k)
				} else if got != v {
					t.Errorf("sanitizeEnvVars()[%q] = %q, want %q", k, got, v)
				}
			}

			for k := range result {
				if _, ok := tt.expected[k]; !ok {
					t.Errorf("sanitizeEnvVars() has unexpected key %q", k)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
