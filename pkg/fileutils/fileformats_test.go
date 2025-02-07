package fileutils

import (
	"fmt"
	"github.com/alecthomas/assert/v2"
	"testing"
)

func TestGenerateFilename(t *testing.T) {
	tests := []struct {
		format      FileFormat
		environment string
		expected    string
	}{
		{Env, "", ".env"},
		{Ejson, "", ".ejson"},
		{Eyaml, "prod", ".eyaml.prod"},
		{Eyml, "staging", ".eyml.staging"},
		{Etoml, "dev", ".etoml.dev"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.format, tt.environment), func(t *testing.T) {
			got := GenerateFilename(tt.format, tt.environment)
			if got != tt.expected {
				t.Errorf("GenerateFilename(%q, %q) = %q; want %q", tt.format, tt.environment, got, tt.expected)
			}
		})
	}
}

func TestParseFormat_ValidFormats(t *testing.T) {
	tests := []struct {
		input    string
		expected FileFormat
	}{
		{".env", Env},
		{".ejson", Ejson},
		{".eyaml", Eyaml},
		{".eyml", Eyml},
		{".etoml", Etoml},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			format, err := ParseFormat(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, format)
		})
	}
}

func TestParseFormat_InvalidFormats(t *testing.T) {
	tests := []string{
		"config.txt",
		"secrets.yaml",
		"data.json",
		"unknown.file",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			format, err := ParseFormat(input)
			assert.Error(t, err)
			assert.Equal(t, format, "")
		})
	}
}
