package commands

import (
	"fmt"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"io"
	"os"
	"strings"
)

type DecryptCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("decrypting secret", "file", c.File, "format", c.Format, "key_dir", c.KeyDir, "key_from_stdin", c.KeyFromStdin)

	var key string
	if c.KeyFromStdin {
		ctx.Logger.Debug("reading private key from stdin")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			ctx.Logger.Debug("stdin read failed", "error", err)
			return fmt.Errorf("error reading from stdin: %v", err)
		}
		key = strings.TrimSpace(string(data))
		ctx.Logger.Debug("private key read from stdin", "key_length", len(key))
	} else {
		ctx.Logger.Debug("using key from keyring", "key_dir", c.KeyDir)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("error processing file or env: %v", err)
	}
	ctx.Logger.Debug("resolved file path", "path", fileName)

	// Check if file exists
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", fileName)
			return fmt.Errorf("file does not exist: %s", fileName)
		}
		ctx.Logger.Debug("error checking file", "path", fileName, "error", err)
		return fmt.Errorf("error checking file %s: %v", fileName, err)
	}
	ctx.Logger.Debug("file details", "path", fileName, "size", fileInfo.Size(), "mode", fileInfo.Mode())

	ctx.Logger.Debug("decrypting file", "path", fileName)
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		ctx.Logger.Debug("decryption failed", "path", fileName, "error", err)
		return fmt.Errorf("error decrypting file %s: %v", fileName, err)
	}

	ctx.Logger.Debug("decryption successful", "path", fileName, "bytes", len(data))
	fmt.Println(string(data))
	return nil
}
