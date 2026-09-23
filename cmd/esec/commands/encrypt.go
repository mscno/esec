package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

// EncryptCmd encrypts a secrets file.
type EncryptCmd struct {
	File   string `arg:"" help:"File or Environment to encrypt" default:""`
	Format string `help:"File format (ejson, env, eyaml, etoml)" default:".ejson" short:"f" env:"ESEC_FORMAT"`
	DryRun bool   `help:"Print the encrypted file to stdout without writing" short:"n"`
	Output string `help:"Write the encrypted output to this file instead of updating in place" short:"o" type:"path"`
}

// Run executes the encrypt command.
func (c *EncryptCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("encrypting secret", "file", c.File, "format", c.Format, "dry_run", c.DryRun, "output", c.Output)

	if c.DryRun && c.Output != "" {
		return fmt.Errorf("--dry-run and --output are mutually exclusive")
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		ctx.Logger.Debug("format parsing failed", "format", c.Format, "error", err)
		return fmt.Errorf("invalid format %q: %w", c.Format, err)
	}
	ctx.Logger.Debug("parsed format", "format_type", format)

	filePath, err := processFileOrEnv(c.File, format)
	if err != nil {
		ctx.Logger.Debug("file/env processing failed", "input", c.File, "error", err)
		return fmt.Errorf("invalid file or environment %q: %w", c.File, err)
	}
	ctx.Logger.Debug("resolved file path", "path", filePath)

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.Logger.Debug("file does not exist", "path", filePath)
			return fmt.Errorf("file does not exist: %s", filePath)
		}
		ctx.Logger.Debug("error checking file", "path", filePath, "error", err)
		return fmt.Errorf("cannot access file %s: %w", filePath, err)
	}
	ctx.Logger.Debug("file details", "path", filePath, "size", fileInfo.Size(), "mode", fileInfo.Mode())

	// Dry run: encrypt to stdout, never modify anything on disk.
	if c.DryRun {
		return encryptFileTo(ctx, filePath, os.Stdout)
	}

	// Output file: encrypt to the given path instead of in place.
	if c.Output != "" {
		var buf bytes.Buffer
		if err := encryptFileTo(ctx, filePath, &buf); err != nil {
			return err
		}
		if err := os.WriteFile(c.Output, buf.Bytes(), fileInfo.Mode()); err != nil {
			return fmt.Errorf("writing output file %s: %w", c.Output, err)
		}
		if !ctx.Quiet {
			fmt.Fprintf(os.Stderr, "Encrypted %s -> %s (%d bytes)\n", filePath, c.Output, buf.Len())
		}
		return nil
	}

	ctx.Logger.Debug("encrypting file in place", "path", filePath)
	n, err := esec.EncryptFileInPlace(filePath)
	if err != nil {
		ctx.Logger.Debug("encryption failed", "path", filePath, "error", err)
		return fmt.Errorf("encrypting file %s: %w", filePath, err)
	}

	ctx.Logger.Debug("encryption successful", "path", filePath, "bytes", n)
	if !ctx.Quiet {
		fmt.Fprintf(os.Stderr, "Encrypted %s (%d bytes)\n", filePath, n)
	}
	return nil
}

// encryptFileTo encrypts the given file and writes the encrypted result to out.
// The format is derived from the file itself. Used for --dry-run (stdout) and
// --output (buffered file write).
func encryptFileTo(ctx *cliCtx, filePath string, out io.Writer) error {
	data, err := os.ReadFile(filePath) //nolint:gosec // File path is user-provided
	if err != nil {
		return fmt.Errorf("reading file %s: %w", filePath, err)
	}

	format, err := fileutils.ParseFormat(filePath)
	if err != nil {
		return fmt.Errorf("determining format of %s: %w", filePath, err)
	}
	ctx.Logger.Debug("encrypting file", "path", filePath, "format", format)

	var buf bytes.Buffer
	if _, err := esec.Encrypt(bytes.NewReader(data), &buf, esec.FileFormat(format)); err != nil {
		return fmt.Errorf("encrypting file %s: %w", filePath, err)
	}

	if err := writeData(out, buf.Bytes()); err != nil {
		return fmt.Errorf("writing encrypted output: %w", err)
	}
	return nil
}
