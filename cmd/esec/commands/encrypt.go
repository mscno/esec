package commands

import (
	"fmt"
	"os"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// EncryptCmd encrypts a secrets file.
type EncryptCmd struct {
	File   string `arg:"" help:"File or Environment to encrypt" default:""`
	Format string `help:"File format" default:".ejson" short:"f"`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

// Run executes the encrypt command.
func (c *EncryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("encrypting secret", "file", c.File, "format", c.Format, "dry_run", c.DryRun)

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	filePath, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("error processing file or env %q: %v", c.File, err)
	}
	ctx.Logger.Debug("resolved file path", "path", filePath)

	// Check if file exists when not in dry run mode
	if !c.DryRun {
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				ctx.Logger.Debug("file does not exist", "path", filePath)
				return fmt.Errorf("file does not exist: %s", filePath)
			}
			ctx.Logger.Debug("error checking file", "path", filePath, "error", err)
			return fmt.Errorf("error checking file %s: %v", filePath, err)
		}
		ctx.Logger.Debug("file details", "path", filePath, "size", fileInfo.Size(), "mode", fileInfo.Mode())
	}

	ctx.Logger.Debug("encrypting file", "path", filePath)
	n, err := esec.EncryptFileInPlace(filePath)
	if err != nil {
		ctx.Logger.Debug("encryption failed", "path", filePath, "error", err)
		return fmt.Errorf("error encrypting file %s: %v", filePath, err)
	}

	ctx.Logger.Debug("encryption successful", "path", filePath, "bytes", n)
	fmt.Printf("Encrypted %d bytes\n", n)
	return nil
}
