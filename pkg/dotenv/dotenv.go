package dotenv

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/format"
)

// validIdentifierPattern matches valid environment variable identifiers
var validIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type DotEnvFormatter struct{}

func (d *DotEnvFormatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	envs, err := godotenv.Parse(bytes.NewReader(data))
	if err != nil {
		return [32]byte{}, err
	}
	return format.ExtractPublicKeyHelper(envs)
}

func (d *DotEnvFormatter) TransformScalarValues(data []byte, fn func([]byte) ([]byte, error)) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var buffer bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()

		// Trim spaces for parsing but keep the original line intact
		trimmedLine := strings.TrimSpace(line)

		// Check if the line is a comment or blank, and write it as-is
		if strings.HasPrefix(trimmedLine, "#") || trimmedLine == "" {
			buffer.WriteString(line + "\n")
			continue
		}

		// Split key and value by the first '=' to handle cases where '=' is in the value
		parts := strings.SplitN(trimmedLine, "=", 2)
		if len(parts) != 2 {
			// Warn if line looks like a malformed key-value pair (valid identifier without '=')
			if isLikelyMalformedEntry(trimmedLine) {
				return nil, fmt.Errorf("line appears malformed (no '=' found): %q", trimmedLine)
			}
			// If line does not match key=value pattern, write it as-is
			buffer.WriteString(line + "\n")
			continue
		}

		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// Skip the public key field and encrypt other values
		if key != format.PublicKeyField {
			encMsg, err := fn([]byte(value))
			if err != nil {
				return nil, err
			}
			// Replace the original value with the encrypted value
			value = string(encMsg)
		}

		// Write the encrypted key-value pair to the buffer
		buffer.WriteString(fmt.Sprintf("%s=%s\n", key, value))
	}

	// Handle any scanning error
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// isLikelyMalformedEntry checks if a line looks like an intended key-value pair
// but is missing the '=' sign. This helps catch typos like "SECRET_KEY" instead of "SECRET_KEY=value"
func isLikelyMalformedEntry(line string) bool {
	// Skip lines that start with export (shell syntax)
	if strings.HasPrefix(line, "export ") {
		return false
	}
	// Skip very short lines
	if len(line) < 3 {
		return false
	}
	// If line matches a valid identifier pattern, it's likely a malformed entry
	return validIdentifierPattern.MatchString(line)
}
