package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// decryptEnvVars decrypts a .env, .ejson or .etoml secrets file, named directly or by
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

	fileName, fileFormat, err := fileutils.Resolve(".", file, formatFlag)
	if err != nil {
		return nil, "", err
	}
	if fileFormat != fileutils.Env && fileFormat != fileutils.Ejson && fileFormat != fileutils.Etoml {
		return nil, "", fmt.Errorf("unsupported format %s: use .env, .ejson or .etoml", fileFormat)
	}

	data, err := readDocument(fileName, formatFlag, keyDir, key)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting file %s: %w", fileName, err)
	}
	vars, err := esec.EnvVars(data, esec.FileFormat(fileFormat))
	if err != nil {
		return nil, "", fmt.Errorf("reading variables from %s: %w", fileName, err)
	}
	return vars, fileName, nil
}
