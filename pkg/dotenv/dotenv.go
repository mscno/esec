package dotenv

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/format"
	"strings"
)

type DotEnvFormatter struct{}

func (d *DotEnvFormatter) ExtractPublicKey(data []byte) ([32]byte, error) {
	envs, err := godotenv.Parse(bytes.NewReader(data))
	if err != nil {
		return [32]byte{}, err
	}
	pubKeyString, ok := envs[format.PublicKeyField]
	if !ok {
		return [32]byte{}, format.ErrPublicKeyMissing
	}

	return format.ParseKey(pubKeyString)
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
