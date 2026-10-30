package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// builtinCommands are the commands handled by esec itself. Anything else may
// be provided by an external `esec-<command>` binary on PATH (git-style
// subcommand passthrough).
var builtinCommands = map[string]bool{
	"inspect":      true,
	"keygen":       true,
	"setup":        true,
	"encrypt":      true,
	"decrypt":      true,
	"export":       true,
	"get":          true,
	"run":          true,
	"capabilities": true,
	"help":         true,
}

// execExternalFn is the platform-specific exec used by the passthrough. It is
// a variable so tests can stub it.
var execExternalFn = execExternal

// maybeExecExternal implements git-style subcommand discovery: if args[1] is
// not a builtin command and an `esec-<name>` executable exists on PATH, it is
// executed with the remaining arguments and the process's exit code is
// returned. The second return value reports whether this happened.
func maybeExecExternal(args []string) (exitCode int, handled bool) {
	if len(args) < 2 {
		return 0, false
	}
	name := args[1]
	if strings.HasPrefix(name, "-") || builtinCommands[name] {
		return 0, false
	}
	// Reject anything that looks like a path; LookPath would otherwise search
	// relative to the current directory.
	if strings.ContainsAny(name, `/\`) {
		return 0, false
	}
	bin, err := exec.LookPath("esec-" + name)
	if err != nil {
		if name == "vault" {
			fmt.Fprintln(os.Stderr, "esec: error: \"esec vault\" runs esec-vault, which is not on PATH. Install it: "+vaultInstall)
			return 1, true
		}
		return 0, false
	}
	return execExternalFn(bin, args[2:]), true
}
