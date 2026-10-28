package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// DecryptCmd decrypts a secrets file.
type DecryptCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string `help:"File format (ejson, env, eyaml, etoml)" default:"" short:"f" env:"ESEC_FORMAT"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec-keyring' file" default:"." short:"d" env:"ESEC_KEY_DIR"`
}

// Run executes the decrypt command.
func (c *DecryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("decrypting secret", "file", c.File, "format", c.Format, "key_dir", c.KeyDir, "key_from_stdin", c.KeyFromStdin)

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

	fileName, _, err := fileutils.Resolve(".", c.File, c.Format)
	if err != nil {
		return err
	}
	ctx.Logger.Debug("resolved file path", "path", fileName)

	// Check if file exists
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", fileName)
			return missingFile(fileName)
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
	if err := writeData(os.Stdout, data); err != nil {
		return fmt.Errorf("writing decrypted output: %w", err)
	}
	return nil
}
