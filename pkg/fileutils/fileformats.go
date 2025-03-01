package fileutils

import (
	"fmt"
	"path/filepath"
	"strings"
)

type FileFormat string

const (
	Env   FileFormat = ".env"
	Ejson FileFormat = ".ejson"
	Eyaml FileFormat = ".eyaml"
	Eyml  FileFormat = ".eyml"
	Etoml FileFormat = ".etoml"
)

func ValidFormats() []FileFormat {
	return []FileFormat{Env, Ejson, Eyaml, Eyml, Etoml}
}

// ParseFormat attempts to determine the format type based on the file prefix.
func ParseFormat(input string) (FileFormat, error) {
	if !strings.HasPrefix(input, ".") {
		input = "." + input
	}
	base := filepath.Base(input)
	for _, format := range ValidFormats() {
		if strings.HasPrefix(base, string(format)) {
			return format, nil
		}
	}

	return "", fmt.Errorf("unsupported format: %s", input)
}

func GenerateFilename(format FileFormat, environment string) string {
	if environment != "" {
		return fmt.Sprintf("%s.%s", format, environment)
	}
	return string(format)
}
