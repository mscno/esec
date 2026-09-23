//go:build !windows

package commands

import (
	"fmt"
	"os"
	"syscall"
)

// execExternal replaces the current process with the given binary, forwarding
// arguments, environment, and the standard file descriptors.
func execExternal(bin string, args []string) int {
	argv := append([]string{bin}, args...)
	//nolint:gosec // bin comes from LookPath("esec-"+name) with name validated to contain no path separators; exec replacement is the feature
	if err := syscall.Exec(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "esec: failed to exec %s: %v\n", bin, err)
		return 1
	}
	return 0 // unreachable
}
