package commands

import (
	"bytes"
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"io"
	"os"
)

/*

 */

type Context struct {
	Debug bool
	//In    *do.Injector
	context.Context
}

type CLI struct {
	Keygen  KeygenCmd  `cmd:"" help:"Generate key"`
	Encrypt EncryptCmd `cmd:"" help:"Encrypt a secret"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt a secret"`
}

func Execute() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.UsageOnError(),
		kong.Name("esec"),
		kong.Description("EncryptedSecrets"),
	)

	err := ctx.Run(&Context{Context: context.Background()})
	ctx.FatalIfErrorf(err)
}

type KeygenCmd struct {
}

func (c *KeygenCmd) Run(ctx *Context) error {
	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		return err
	}

	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}

type EncryptCmd struct {
	File   string `arg:"" help:"Message to encrypt" default:""`
	DryRun bool   `help:"Print the encrypted message without writing to file" short:"d"`
}

func (c *EncryptCmd) Run(ctx *Context) error {
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
	//format, err := esec.DetectFormat(c.File)
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

	n, err := esec.EncryptFileInPlace(c.File)
	fmt.Printf("Encrypted %d bytes\n", n)
	return err
}

type DecryptCmd struct {
	File         string `arg:"" help:"File to decrypt" default:""`
	Format       string `help:"File format" default:".ejson" short:"f"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec_keyring' file" default:"." short:"d"`
}

func (c *DecryptCmd) Run(ctx *Context) error {
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
	}

	var buf bytes.Buffer
	data, err := esec.DecryptFile(c.File, c.KeyDir, key)
	if err != nil {
		return err
	}
	buf.Read(data)
	fmt.Println(string(data))
	return nil
}
