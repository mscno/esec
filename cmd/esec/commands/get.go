package commands

import (
	gojson "encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// GetCmd decrypts a secrets file and extracts a specific key.
type GetCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Key          string `arg:"" help:"Key to extract from decrypted content" default:""`
	Format       string `help:"File format (ejson, env, eyaml, etoml)" default:".ejson" short:"f" env:"ESEC_FORMAT"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec-keyring' file" default:"." short:"d" env:"ESEC_KEY_DIR"`
}

// Run executes the get command.
func (c *GetCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("getting key from secret", "file", c.File, "key", c.Key, "format", c.Format, "key_dir", c.KeyDir, "key_from_stdin", c.KeyFromStdin)

	var key string
	if c.KeyFromStdin {
		ctx.Logger.Debug("reading private key from stdin")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			ctx.Logger.Debug("stdin read failed", "error", err)
			return fmt.Errorf("reading key from stdin: %w", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("private key read from stdin", "key_length", len(key))
	} else {
		ctx.Logger.Debug("using key from keyring", "key_dir", c.KeyDir)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("invalid format %q: %w", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("invalid file or environment %q: %w", c.File, err)
	}
	ctx.Logger.Debug("resolved file path", "path", fileName)

	// The actual format is determined by the file on disk; the --format flag
	// only controls how an environment name is resolved to a file name.
	fileFormat, err := fileutils.ParseFormat(fileName)
	if err != nil {
		return fmt.Errorf("determining format of %s: %w", fileName, err)
	}

	// Check if file exists
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", fileName)
			return fmt.Errorf("file does not exist: %s", fileName)
		}
		ctx.Logger.Debug("error checking file", "path", fileName, "error", err)
		return fmt.Errorf("cannot access file %s: %w", fileName, err)
	}
	ctx.Logger.Debug("file details", "path", fileName, "size", fileInfo.Size(), "mode", fileInfo.Mode())

	ctx.Logger.Debug("decrypting file", "path", fileName)
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		ctx.Logger.Debug("decryption failed", "path", fileName, "error", err)
		return fmt.Errorf("decrypting file %s: %w", fileName, err)
	}

	ctx.Logger.Debug("decryption successful", "path", fileName, "bytes", len(data))

	// Parse the data based on format and extract the key
	var value string

	switch fileFormat {
	case fileutils.Env:
		// Parse .env format
		envVars, err := esec.DotEnvToEnv(data)
		if err != nil {
			ctx.Logger.Debug("env parsing failed", "error", err)
			return fmt.Errorf("parsing decrypted .env: %w", err)
		}
		val, exists := envVars[c.Key]
		if !exists {
			ctx.Logger.Debug("key not found", "key", c.Key)
			return fmt.Errorf("key %q not found in decrypted content", c.Key)
		}
		value = val

	case fileutils.Ejson:
		// Parse JSON format
		var jsonData map[string]interface{}
		if err := gojson.Unmarshal(data, &jsonData); err != nil {
			ctx.Logger.Debug("json parsing failed", "error", err)
			return fmt.Errorf("parsing decrypted JSON: %w", err)
		}

		// Handle nested keys with dot notation
		keys := strings.Split(c.Key, ".")
		current := jsonData

		// Navigate through nested objects
		for i, k := range keys[:len(keys)-1] {
			nextObj, ok := current[k].(map[string]interface{})
			if !ok {
				ctx.Logger.Debug("invalid key path", "key", c.Key, "failed_at", strings.Join(keys[:i+1], "."))
				return fmt.Errorf("key path %q is invalid at %q", c.Key, strings.Join(keys[:i+1], "."))
			}
			current = nextObj
		}

		// Get the final value
		lastKey := keys[len(keys)-1]
		val, exists := current[lastKey]
		if !exists {
			ctx.Logger.Debug("key not found", "key", c.Key)
			return fmt.Errorf("key %q not found in decrypted content", c.Key)
		}

		// Convert the value to string based on type
		switch v := val.(type) {
		case string:
			value = v
		case float64, int, bool:
			value = fmt.Sprintf("%v", v)
		default:
			// For complex objects, return as JSON
			valueBytes, err := gojson.Marshal(v)
			if err != nil {
				ctx.Logger.Debug("json marshaling failed", "key", c.Key, "error", err)
				return fmt.Errorf("serializing value for key %q: %w", c.Key, err)
			}
			value = string(valueBytes)
		}

	default:
		return fmt.Errorf("unsupported format for get command: %s", fileFormat)
	}

	// Output just the value without newline
	fmt.Print(value)
	return nil
}
