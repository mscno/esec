package dotenv

import (
	"strings"
	"testing"
)

func TestTransformScalarValues(t *testing.T) {
	formatter := &Formatter{}

	// Identity transform for testing
	identityFn := func(b []byte) ([]byte, error) {
		return b, nil
	}

	// Transform that wraps values in brackets
	bracketFn := func(b []byte) ([]byte, error) {
		return []byte("[" + string(b) + "]"), nil
	}

	tests := []struct {
		name        string
		input       string
		transformFn func([]byte) ([]byte, error)
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "simple key=value",
			input:       "FOO=bar\n",
			transformFn: identityFn,
			want:        "FOO=bar\n",
		},
		{
			name:        "transforms value",
			input:       "FOO=bar\n",
			transformFn: bracketFn,
			want:        "FOO=[bar]\n",
		},
		{
			name:        "preserves ESEC_PUBLIC_KEY",
			input:       "ESEC_PUBLIC_KEY=mykey123\nSECRET=value\n",
			transformFn: bracketFn,
			want:        "ESEC_PUBLIC_KEY=mykey123\nSECRET=[value]\n",
		},
		{
			name:        "preserves comments",
			input:       "# This is a comment\nFOO=bar\n",
			transformFn: bracketFn,
			want:        "# This is a comment\nFOO=[bar]\n",
		},
		{
			name:        "preserves blank lines",
			input:       "FOO=bar\n\nBAZ=qux\n",
			transformFn: bracketFn,
			want:        "FOO=[bar]\n\nBAZ=[qux]\n",
		},
		{
			name:        "handles values with equals sign",
			input:       "DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require\n",
			transformFn: identityFn,
			want:        "DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require\n",
		},
		{
			name:        "handles empty value",
			input:       "EMPTY=\n",
			transformFn: bracketFn,
			want:        "EMPTY=[]\n",
		},
		{
			name:        "handles multiple entries",
			input:       "A=1\nB=2\nC=3\n",
			transformFn: bracketFn,
			want:        "A=[1]\nB=[2]\nC=[3]\n",
		},
		{
			name:        "preserves indented comments",
			input:       "  # indented comment\nFOO=bar\n",
			transformFn: identityFn,
			want:        "  # indented comment\nFOO=bar\n",
		},
		{
			name:        "malformed entry - valid identifier without equals",
			input:       "SECRET_KEY\n",
			transformFn: identityFn,
			wantErr:     true,
			errContains: "malformed",
		},
		{
			name:        "malformed entry - uppercase identifier",
			input:       "DATABASE_URL\n",
			transformFn: identityFn,
			wantErr:     true,
			errContains: "malformed",
		},
		{
			name:        "not malformed - export statement",
			input:       "export FOO\nBAR=baz\n",
			transformFn: identityFn,
			want:        "export FOO\nBAR=baz\n",
		},
		{
			name:        "not malformed - short line",
			input:       "xy\nFOO=bar\n",
			transformFn: identityFn,
			want:        "xy\nFOO=bar\n",
		},
		{
			name:        "not malformed - contains special chars",
			input:       "some-text-here\nFOO=bar\n",
			transformFn: identityFn,
			want:        "some-text-here\nFOO=bar\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatter.TransformScalarValues([]byte(tt.input), tt.transformFn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("TransformScalarValues() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("TransformScalarValues() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("TransformScalarValues() unexpected error = %v", err)
				return
			}

			if string(result) != tt.want {
				t.Errorf("TransformScalarValues() = %q, want %q", string(result), tt.want)
			}
		})
	}
}

func TestTransformScalarValuesErrorPropagation(t *testing.T) {
	formatter := &Formatter{}

	// Transform that returns an error
	errorFn := func(b []byte) ([]byte, error) {
		return nil, errTestTransform
	}

	input := "FOO=bar\n"
	_, err := formatter.TransformScalarValues([]byte(input), errorFn)

	if err == nil {
		t.Error("TransformScalarValues() expected error from transform function, got nil")
	}
}

var errTestTransform = &testError{msg: "transform error"}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestExtractPublicKey(t *testing.T) {
	formatter := &Formatter{}

	validKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid public key",
			input:   "ESEC_PUBLIC_KEY=" + validKey + "\nSECRET=value\n",
			wantErr: false,
		},
		{
			name:    "missing public key",
			input:   "SECRET=value\n",
			wantErr: true,
		},
		{
			name:    "invalid public key format",
			input:   "ESEC_PUBLIC_KEY=invalid\nSECRET=value\n",
			wantErr: true,
		},
		{
			name:    "underscore public key",
			input:   "_ESEC_PUBLIC_KEY=" + validKey + "\nSECRET=value\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := formatter.ExtractPublicKey([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Error("ExtractPublicKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ExtractPublicKey() unexpected error = %v", err)
			}
		})
	}
}

func TestIsLikelyMalformedEntry(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"valid identifier", "SECRET_KEY", true},
		{"valid identifier with underscore prefix", "_SECRET", true},
		{"valid single letter", "A", false}, // too short
		{"valid two letters", "AB", false},  // too short
		{"valid three letters", "ABC", true},
		{"export statement", "export FOO", false},
		{"contains hyphen", "some-var", false},
		{"contains space", "some var", false},
		{"contains equals", "some=var", false},
		{"starts with number", "1VAR", false},
		{"empty", "", false},
		{"just underscore", "_", false}, // too short
		{"uppercase with numbers", "VAR123", true},
		{"lowercase with numbers", "var123", true},
		{"mixed case", "VarName", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyMalformedEntry(tt.line)
			if got != tt.want {
				t.Errorf("isLikelyMalformedEntry(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}
