package commands

import (
	"errors"
	"io"
	"os"

	"github.com/mscno/esec"
)

// SetCmd encrypts a value without putting plaintext into command arguments.
type SetCmd struct {
	File   string `arg:"" help:"Environment or secrets file"`
	Key    string `arg:"" help:"Key name or dotted field path"`
	Stdin  bool   `help:"Read the exact value bytes from stdin, including trailing newlines"`
	Create bool   `help:"Explicitly add a missing key (dotenv or YAML)"`
}

// Run snapshots the file before prompting and saves only verified ciphertext.
func (c *SetCmd) Run(ctx *cliCtx) error {
	t, err := esec.ResolveRead(".", c.File, "")
	if err != nil {
		return errors.New("cannot resolve secrets file or access metadata; use esec check")
	}
	value, err := c.readValue()
	if err != nil {
		return err
	}
	if _, err := updateSecretDocument(t.Path, secretUpdate{Revision: t.Digest, Key: c.Key, Value: &value, Create: c.Create}); err != nil {
		return err
	}
	say(ctx, "Saved %s in %s encrypted.", c.Key, t.Environment)
	return nil
}

func (c *SetCmd) readValue() (string, error) {
	const limit = 1 << 20
	if c.Stdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
		defer clear(b)
		if err != nil || len(b) > limit {
			return "", errors.New("could not read value: maximum size is 1 MiB")
		}
		return string(b), nil
	}
	terminal, err := openRecoveryTerminal()
	if err != nil {
		return "", errors.New("set requires a private terminal prompt or --stdin; values are never accepted as arguments")
	}
	defer terminal.Close()
	value, err := terminal.Secret("New value (hidden): ")
	if err != nil {
		return "", err
	}
	confirmation, err := terminal.Secret("Confirm value (hidden): ")
	if err != nil {
		return "", err
	}
	if value != confirmation {
		return "", errors.New("values did not match; nothing was saved")
	}
	if len(value) > limit {
		return "", errors.New("maximum value size is 1 MiB")
	}
	return value, nil
}
