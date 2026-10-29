package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mscno/esec"
)

// viaVault hands a read that failed on a guarded environment's key to
// esec-vault, whose background service opens that key after the person's
// dialog and touch: esec itself is never given the key. It returns err
// unchanged unless the key is guarded and sealed, file names an environment
// (a path is resolved by esec alone), and esec-vault is on PATH; otherwise
// it runs esec vault with the arguments args builds for that environment
// and returns its exit code.
func viaVault(err error, file string, args func(env string) []string) error {
	var nf *esec.KeyNotFoundError
	if !errors.As(err, &nf) || !nf.Guarded || nf.Sealed == "" {
		return err
	}
	if file == "" || strings.ContainsAny(file, `/\`) || strings.HasPrefix(file, ".") {
		return err
	}
	bin, lookErr := exec.LookPath("esec-vault")
	if lookErr != nil {
		return err
	}
	env := strings.TrimSuffix(filepath.Base(nf.Sealed), ".age")
	a := args(env)
	fmt.Fprintf(os.Stderr, "esec: %s is guarded: reading it through esec vault %s, which asks for your touch\n", env, a[0])
	return &ExitError{Code: execExternalFn(bin, a)}
}

// withFormat adds --format to args when one was given.
func withFormat(args []string, format string) []string {
	if format == "" {
		return args
	}
	return append(args, "--format", format)
}
