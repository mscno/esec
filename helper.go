package esec

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// detectFormat attempts to determine the format type based on the file prefix.
func detectFormat(input string) (FormatType, error) {
	validFormats := map[FormatType]bool{
		Env: true, Ejson: true, Eyaml: true, Eyml: true, Etoml: true,
	}

	for format := range validFormats {
		if strings.HasPrefix(filepath.Base(input), string(format)) {
			return format, nil
		}
	}

	return "", fmt.Errorf("unsupported format: %s", input)
}

const defaultFormat = Ejson

func processFileOrEnv(input string) (filename string, environment string, err error) {
	// First, check if it's a valid filename by looking for valid prefixes
	validFormats := map[FormatType]bool{
		Env:   true,
		Ejson: true,
		Eyaml: true,
		Eyml:  true,
		Etoml: true,
	}

	// Check if input starts with any valid format
	isFile := false
	for format := range validFormats {
		if strings.Contains(path.Base(input), string(format)) {
			isFile = true
			break
		}
	}

	if isFile {
		// Input is a filename, parse the environment from it
		environment, err = parseEnvironment(path.Base(input))
		if err != nil {
			return "", "", fmt.Errorf("invalid filename: %v", err)
		}
		return input, environment, nil
	}

	// Input is treated as an environment
	environment = input
	// Validate environment string
	if strings.ContainsAny(environment, ".\\/") {
		return "", "", fmt.Errorf("invalid environment name: %s - should not contain dots or path separators", input)
	}

	for _, char := range environment {
		if !strings.Contains("abcdefghijklmnopqrstuvwxyz0123456789", string(char)) {
			return "", "", fmt.Errorf("invalid environment name: %s - should be lowercase alphanumeric", input)
		}
	}

	if !isFile {
		// Generate filename using the default format (.env)
		filename, err = generateFilename(defaultFormat, environment)
		if err != nil {
			return "", "", fmt.Errorf("error generating filename: %v", err)
		}
	}

	return filename, input, nil
}

// Helper functions from before
func parseEnvironment(filename string) (string, error) {
	base := filename

	validPrefixes := []string{string(Env), string(Ejson), string(Eyaml), string(Eyml), string(Etoml)}
	isValidPrefix := false
	for _, prefix := range validPrefixes {
		base = path.Base(filename)
		if strings.HasPrefix(base, prefix) {
			isValidPrefix = true
			break
		}
	}

	if !isValidPrefix {
		return "", fmt.Errorf("invalid file type: %s", filename)
	}

	parts := strings.Split(base, ".")
	if len(parts) <= 2 {
		return "", nil
	}

	return parts[len(parts)-1], nil
}

func generateFilename(format FormatType, environment string) (string, error) {
	validFormats := map[FormatType]bool{
		Env: true, Ejson: true, Eyaml: true, Eyml: true, Etoml: true,
	}

	if !validFormats[format] {
		return "", fmt.Errorf("invalid format: %s", format)
	}

	if environment == "" {
		return string(format), nil
	}

	return fmt.Sprintf("%s.%s", format, environment), nil
}

func sniffEnvName() (string, error) {
	var setKeys []string

	// Scan environment variables for keys starting with ESEC_PRIVATE_KEY
	for _, envVar := range os.Environ() {
		if strings.HasPrefix(envVar, ESEC_PRIVATE_KEY) {
			key := strings.SplitN(envVar, "=", 2)[0]
			setKeys = append(setKeys, key)
		}
	}

	switch len(setKeys) {
	case 0:
		return "", nil // Default to "" (blank env) if no key is found
	case 1:
		// Extract the environment name from the key
		if setKeys[0] == ESEC_PRIVATE_KEY {
			return "", nil
		}
		return strings.ToLower(strings.TrimPrefix(setKeys[0], ESEC_PRIVATE_KEY+"_")), nil
	default:
		return "", fmt.Errorf("multiple private keys found: %v", setKeys)
	}
}
