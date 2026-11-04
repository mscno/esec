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
	"recovery": true, "plan": true, "apply": true, "status": true,
	"files": true, "secrets": true, "init": true, "identity": true, "recipients": true, "rotate": true, "adopt": true, "repair": true,
	"inspect": true,
	"keygen":  true,
	"setup":   true,
	"encrypt": true,
	"decrypt": true,
	"export":  true,
	"get":     true,
	"run":     true,
	"help":    true,
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
	if retiredCommand(name) {
		fmt.Fprintf(os.Stderr, "esec: command %q was retired; use esec setup and esec init, or esec adopt for an existing environment\n", name)
		return 1, true
	}
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
		return 0, false
	}
	return execExternalFn(bin, args[2:]), true
}

// Retired service commands cannot be revived by stale executables on PATH.
func retiredCommand(name string) bool {
	name = strings.ToLower(name)
	return name == "vault" || strings.HasPrefix(name, "vault-") || name == "legacy-setup" || name == "broker" || name == "daemon"
}
