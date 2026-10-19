package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// decryptEnvVars decrypts a .env or .ejson secrets file, named directly or by
// environment, and returns its values as environment variables without the
// public key. It is shared by run and export.
func decryptEnvVars(ctx *cliCtx, file, formatFlag, keyDir string, keyFromStdin bool) (map[string]string, string, error) {
	var key string
	if keyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("reading key from stdin: %w", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("read private key from stdin")
	}

	// The --format flag only resolves an environment name to a file name.
	format, err := fileutils.ParseFormat(formatFlag)
	if err != nil {
		return nil, "", fmt.Errorf("invalid format %q: %w", formatFlag, err)
	}
	fileName, err := processFileOrEnv(file, format)
	if err != nil {
		return nil, "", fmt.Errorf("invalid file or environment %q: %w", file, err)
	}
	ctx.Logger.Debug("using secrets file", "file", fileName)

	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return nil, "", fmt.Errorf("secrets file %s does not exist", fileName)
	}

	// The actual format is determined by the file on disk.
	fileFormat, err := fileutils.ParseFormat(fileName)
	if err != nil {
		return nil, "", fmt.Errorf("determining format of %s: %w", fileName, err)
	}
	if fileFormat != fileutils.Env && fileFormat != fileutils.Ejson {
		return nil, "", fmt.Errorf("unsupported format %s: only .env and .ejson files hold environment variables", fileFormat)
	}

	data, err := esec.DecryptFile(fileName, keyDir, key)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting file %s: %w", fileName, err)
	}
	vars, err := esec.EnvVars(data, esec.FileFormat(fileFormat))
	if err != nil {
		return nil, "", fmt.Errorf("reading variables from %s: %w", fileName, err)
	}
	return vars, fileName, nil
}
