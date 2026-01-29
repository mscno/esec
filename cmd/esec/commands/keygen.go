package commands

import (
	"fmt"

	"github.com/mscno/esec"
)

type KeygenCmd struct {
}

func (c *KeygenCmd) Run(ctx *cliCtx) error {
	ctx.Logger.Debug("generating new keypair")

	pub, priv, err := esec.GenerateKeypair()
	if err != nil {
		ctx.Logger.Debug("keypair generation failed", "error", err)
		return err
	}

	ctx.Logger.Debug("keypair generated successfully")
	fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	return nil
}
