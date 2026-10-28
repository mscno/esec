// Package fileutils provides utilities for working with encrypted file formats.
package fileutils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FileFormat represents the supported encrypted file format extensions.
type FileFormat string

// Supported file format extensions.
const (
	// Env represents the .env (dotenv) file format.
	Env FileFormat = ".env"
	// Ejson represents the .ejson (encrypted JSON) file format.
	Ejson FileFormat = ".ejson"
	// Eyaml represents the .eyaml (encrypted YAML) file format.
	Eyaml FileFormat = ".eyaml"
	// Eyml represents the .eyml (encrypted YAML) file format.
	Eyml FileFormat = ".eyml"
	// Etoml represents the .etoml (encrypted TOML) file format.
	Etoml FileFormat = ".etoml"
)

// ValidFormats returns a slice of all supported file formats.
func ValidFormats() []FileFormat {
	return []FileFormat{Env, Ejson, Eyaml, Eyml, Etoml}
}

// ParseFormat determines the file format based on the filename or format string.
// It accepts inputs like ".ejson", "ejson", ".ejson.dev", or full paths like "/path/to/.ejson.dev".
// Returns an error if the format is not recognized.
func ParseFormat(input string) (FileFormat, error) {
	base := filepath.Base(input)
	for _, format := range ValidFormats() {
		f := string(format)
		if base == f || base == strings.TrimPrefix(f, ".") || strings.HasPrefix(base, f) || strings.HasSuffix(base, f) {
			return format, nil
		}
	}

	return "", fmt.Errorf("unsupported format: %s", input)
}

// GenerateFilename creates a filename from a format and optional environment name.
// For example, GenerateFilename(Ejson, "dev") returns ".ejson.dev",
// and GenerateFilename(Ejson, "") returns ".ejson".
func GenerateFilename(format FileFormat, environment string) string {
	if environment != "" {
		return fmt.Sprintf("%s.%s", format, environment)
	}
	return string(format)
}

// Environment returns the environment suffix from either supported naming style.
func Environment(filename string) string {
	f, err := ParseFormat(filename)
	if err != nil {
		return ""
	}
	base := filepath.Base(filename)
	if base == string(f) {
		return ""
	}
	if strings.HasPrefix(base, string(f)+".") {
		return strings.TrimPrefix(base, string(f)+".")
	}
	if strings.HasSuffix(base, string(f)) {
		return strings.TrimSuffix(base, string(f))
	}
	return ""
}
