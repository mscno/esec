package format

import (
	"errors"
	"testing"
)

func TestParseKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 64-char lowercase hex key",
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "valid 64-char uppercase hex key",
			input:   "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			wantErr: false,
		},
		{
			name:    "valid 64-char mixed case hex key",
			input:   "0123456789AbCdEf0123456789aBcDeF0123456789ABCdef0123456789abcDEF",
			wantErr: false,
		},
		{
			name:    "too short key",
			input:   "0123456789abcdef",
			wantErr: true,
			errMsg:  "not 64 characters",
		},
		{
			name:    "too long key",
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			wantErr: true,
			errMsg:  "not 64 characters",
		},
		{
			name:    "empty key",
			input:   "",
			wantErr: true,
			errMsg:  "not 64 characters",
		},
		{
			name:    "invalid hex characters (g)",
			input:   "0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "invalid hex characters (special chars)",
			input:   "0123456789abcdef!@#$%^&*()abcdef0123456789abcdef0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "63 characters (one short)",
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			wantErr: true,
			errMsg:  "not 64 characters",
		},
		{
			name:    "65 characters (one long)",
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa",
			wantErr: true,
			errMsg:  "not 64 characters",
		},
		{
			name:    "all zeros",
			input:   "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		{
			name:    "all f's",
			input:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseKey() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("ParseKey() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ParseKey() unexpected error = %v", err)
					return
				}
				// Verify the key is 32 bytes
				if len(key) != 32 {
					t.Errorf("ParseKey() returned key with length %d, want 32", len(key))
				}
			}
		})
	}
}

func TestParseKeyDeterministic(t *testing.T) {
	input := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	key1, err1 := ParseKey(input)
	key2, err2 := ParseKey(input)

	if err1 != nil || err2 != nil {
		t.Fatalf("ParseKey() unexpected errors: %v, %v", err1, err2)
	}

	if key1 != key2 {
		t.Errorf("ParseKey() not deterministic: got different results for same input")
	}
}

func TestExtractPublicKeyHelper(t *testing.T) {
	validKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name    string
		obj     map[string]interface{}
		wantErr error
	}{
		{
			name: "ESEC_PUBLIC_KEY present",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": validKey,
				"other_key":       "value",
			},
			wantErr: nil,
		},
		{
			name: "_ESEC_PUBLIC_KEY present (preferred)",
			obj: map[string]interface{}{
				"_ESEC_PUBLIC_KEY": validKey,
				"other_key":        "value",
			},
			wantErr: nil,
		},
		{
			name: "both keys present (underscore preferred)",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"_ESEC_PUBLIC_KEY": validKey,
			},
			wantErr: nil,
		},
		{
			name: "key missing",
			obj: map[string]interface{}{
				"other_key": "value",
			},
			wantErr: ErrPublicKeyMissing,
		},
		{
			name:    "empty map",
			obj:     map[string]interface{}{},
			wantErr: ErrPublicKeyMissing,
		},
		{
			name: "key is not a string (int)",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": 12345,
			},
			wantErr: ErrPublicKeyInvalid,
		},
		{
			name: "key is not a string (nil)",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": nil,
			},
			wantErr: ErrPublicKeyInvalid,
		},
		{
			name: "key is not a string (bool)",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": true,
			},
			wantErr: ErrPublicKeyInvalid,
		},
		{
			name: "key is invalid hex",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": "not-a-valid-hex-key",
			},
			wantErr: ErrPublicKeyInvalid,
		},
		{
			name: "key is wrong length",
			obj: map[string]interface{}{
				"ESEC_PUBLIC_KEY": "0123456789abcdef",
			},
			wantErr: ErrPublicKeyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ExtractPublicKeyHelper(tt.obj)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ExtractPublicKeyHelper() expected error, got nil")
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ExtractPublicKeyHelper() error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("ExtractPublicKeyHelper() unexpected error = %v", err)
					return
				}
				if len(key) != 32 {
					t.Errorf("ExtractPublicKeyHelper() returned key with length %d, want 32", len(key))
				}
			}
		})
	}
}

func TestExtractPublicKeyHelperWithStringMap(t *testing.T) {
	validKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name    string
		obj     map[string]string
		wantErr error
	}{
		{
			name: "ESEC_PUBLIC_KEY present",
			obj: map[string]string{
				"ESEC_PUBLIC_KEY": validKey,
				"other_key":       "value",
			},
			wantErr: nil,
		},
		{
			name: "_ESEC_PUBLIC_KEY present",
			obj: map[string]string{
				"_ESEC_PUBLIC_KEY": validKey,
			},
			wantErr: nil,
		},
		{
			name: "key missing",
			obj: map[string]string{
				"other_key": "value",
			},
			wantErr: ErrPublicKeyMissing,
		},
		{
			name: "key is invalid",
			obj: map[string]string{
				"ESEC_PUBLIC_KEY": "invalid",
			},
			wantErr: ErrPublicKeyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ExtractPublicKeyHelper(tt.obj)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ExtractPublicKeyHelper() expected error, got nil")
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ExtractPublicKeyHelper() error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("ExtractPublicKeyHelper() unexpected error = %v", err)
					return
				}
				if len(key) != 32 {
					t.Errorf("ExtractPublicKeyHelper() returned key with length %d, want 32", len(key))
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
