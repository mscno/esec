package commands

import (
	"fmt"

	"github.com/mscno/esec/pkg/keyringfile"
)

// CapabilitiesCmd prints optional features this build supports, one per line.
// esec-vault calls it before sealing keyrings: an esec that does not know the
// command cannot read sealed keyrings either.
type CapabilitiesCmd struct{}

// Run implements the capabilities command.
func (c *CapabilitiesCmd) Run(_ *cliCtx) error {
	fmt.Println(keyringfile.Capability)
	return nil
}
