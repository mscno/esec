package commands

import (
	"bytes"
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"io"
	"os"
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
	File   string `arg:"" help:"Message to encrypt" default:""`
	Format string `help:"File format" default:".ejson" short:"f"`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

func (c *EncryptCmd) Run(ctx *cliCtx) error {
	//var data []byte
	//var err error
	//if c.File != "" {
	//	data, err = os.ReadFile(c.File)
	//	if err != nil {
	//		return err
	//	}
	//}
	//if c.File == "" {
	//	data, err = io.ReadAll(os.Stdin)
	//	if err != nil {
	//		return err
	//	}
	//}
	//
	//format, err := esec.detectFormat(c.File)
	//if err != nil {
	//	return err
	//}
	//
	//bs := bytes.NewReader(data)
	//var buf bytes.Buffer
	//_, err = esec.Encrypt(bs, &buf, format)
	//if err != nil {
	//	return err
	//}
	//if c.File != "" && !c.DryRun {
	//	err = os.WriteFile(c.File, buf.Bytes(), 0644)
	//	if err != nil {
	//		return err
	//	}
	//} else {
	//	fmt.Println(buf.String())
	//}

	format, err := esec.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	n, err := esec.EncryptInputInPlace(c.File, format)
	fmt.Printf("Encrypted %d bytes\n", n)
	return err
}

type DecryptCmd struct {
	File         string `arg:"" help:"File to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *cliCtx) error {
	//var reader io.Reader
	//if c.File != "" {
	//	file, err := os.Open(c.File)
	//	if err != nil {
	//		return err
	//	}
	//	defer file.Close()
	//	reader = file
	//} else {
	//	reader = os.Stdin
	//}

	var key string
	if c.KeyFromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key = string(data)
		key = strings.TrimSpace(key)
	}

	format, err := esec.ParseFormat(c.Format)
	if err != nil {
		return fmt.Errorf("error parsing format flag %q: %v", c.Format, err)
	}

	var buf bytes.Buffer
	data, err := esec.DecryptInput(c.File, c.KeyDir, key, format)
	if err != nil {
		return err
	}
	buf.Read(data)
	fmt.Println(string(data))
	return nil
}
