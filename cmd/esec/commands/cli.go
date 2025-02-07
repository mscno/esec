package commands

import (
	"bytes"
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"io"
	"os"
	"path"
	"strings"
)

type cliCtx struct {
	Debug bool
	context.Context
}

type cli struct {
	Keygen  KeygenCmd        `cmd:"" help:"Generate key"`
	Encrypt EncryptCmd       `cmd:"" help:"Encrypt a secret"`
	Decrypt DecryptCmd       `cmd:"" help:"Decrypt a secret"`
	Version kong.VersionFlag `help:"Show version"`
}

func Execute(version string) {
	var cli cli
	ctx := kong.Parse(&cli,
		kong.UsageOnError(),
		kong.Name("esec"),
		kong.Description("esec is a tool for encrypting secrets"),
		kong.Vars{"version": version},
	)

	err := ctx.Run(&cliCtx{Context: context.Background()})
	ctx.FatalIfErrorf(err)
}

type KeygenCmd struct {
}

func (c *KeygenCmd) Run(ctx *cliCtx) error {
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}

	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}

type EncryptCmd struct {
	File   string `arg:"" help:"File or Environment to encrypt" default:""`
	Format string `help:"File format" default:".ejson" short:"f"`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

func (c *EncryptCmd) Run(ctx *cliCtx) error {
	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	filePath, err := processFileOrEnv(c.File, format)
	if err != nil {
		return fmt.Errorf("error processing file or env %q: %v", c.File, err)
	}

	n, err := esec.EncryptFileInPlace(filePath)
	fmt.Printf("Encrypted %d bytes\n", n)
	return err
}

type DecryptCmd struct {
	File         string `arg:"" help:"File or Environment to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *cliCtx) error {
	var key string
	if c.KeyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key = string(data)
		key = strings.TrimSpace(key)
	}

	format, err := fileutils.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	fileName, err := processFileOrEnv(c.File, format)
	if err != nil {
		fmt.Errorf("error processing file or env: %v", err)
	}

	var buf bytes.Buffer
	data, err := esec.DecryptFile(fileName, c.KeyDir, key)
	if err != nil {
		return err
	}

	buf.Read(data)
	fmt.Println(string(data))
	return nil
}

func processFileOrEnv(input string, defaultFileFormat fileutils.FileFormat) (filename string, err error) {
	// Check if input starts with any valid format
	isFile := false
	for _, format := range fileutils.ValidFormats() {
		if strings.Contains(path.Base(input), string(format)) {
			isFile = true
			break
		}
	}

	if isFile {
		return input, nil
	}

	// Input is treated as an environment
	environment := input
	// Validate environment string
	if strings.ContainsAny(environment, ".\\/") {
		return "", fmt.Errorf("invalid environment name: %s - should not contain dots or path separators", input)
	}

	for _, char := range environment {
		if !strings.Contains("abcdefghijklmnopqrstuvwxyz0123456789", string(char)) {
			return "", fmt.Errorf("invalid environment name: %s - should be lowercase alphanumeric", input)
		}
	}

	// Generate filename using the default format (.env)
	filename = fileutils.GenerateFilename(defaultFileFormat, environment)
	return path.Clean(filename), nil
}
