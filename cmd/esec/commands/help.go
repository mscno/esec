package commands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
)

const description = `esec encrypts and decrypts secrets files using public-key cryptography.

A secrets file (.env, .ejson, .eyaml or .etoml, with an environment suffix such as .env.prod) holds its public key and encrypted values, and is committed. Its private key stays out of the repository: in the variable ESEC_PRIVATE_KEY_<ENV> (ESEC_PRIVATE_KEY_PROD for .env.prod), in a .esec-keyring file, in the global keyring that esec vault manages, or sealed in the repository (.esec/<env>.age) for a reader whose age identity is in ESEC_AGE_IDENTITY or ESEC_AGE_IDENTITY_FILE (CI, deploys).

Commands take a filename or discover an environment across supported formats and naming patterns. "prod" also searches "production". Multiple matches fail; use --format or an explicit path. Preferences live in ~/.config/esec/config.toml.

    esec keygen                        # a key pair to start a file with
    esec setup                         # wizard: project, environments, files and keys
    esec encrypt prod                  # discover and encrypt the matching file
    esec decrypt prod                  # print it decrypted
    esec get prod DATABASE_URL         # print one value
    esec export .env.prod              # NAME=value lines
    esec run prod -- ./server          # run with the values as environment variables

Scripts and agents: output goes to stdout and messages to stderr; "esec help <command>" explains one. Exit codes: 0 done, 1 failed, 80 bad usage; run returns its command's code.`

// commandDetails are the explanations and examples "esec <command> --help"
// shows, by command path.
var commandDetails = map[string]string{
	"setup": `Creates a project, or adds environments to the one already here. It writes esec.toml, a key and a secrets file for each environment. With esec-vault signed in, it checks that the name is free and stores the keys through vault. Without that, pass --local to keep keys on this machine only. This is not "esec vault setup", which creates your personal identity.

` + examples(
		"esec setup",
		"esec setup --project acme/store --env dev,staging,production --format env --yes",
		"esec setup --add --env ops --yes",
	),
	"keygen": `Prints a new key pair. Put the public key in the secrets file as _ESEC_PUBLIC_KEY (ejson) or ESEC_PUBLIC_KEY (env), and keep the private key out of the repository.

` + examples(
		"esec keygen",
		"esec keygen --save --env prod     # keep the private key in the global keyring; print the public key",
	),
	"encrypt": `Encrypts every value not encrypted yet, with the file's public key. No private key is needed.

` + examples(
		"esec encrypt prod                 # discover exactly one file",
		"esec encrypt .env.prod",
		"esec encrypt prod --dry-run       # print, change nothing",
	),
	"decrypt": examples(
		"esec decrypt prod",
		"esec decrypt .env.prod",
		"echo $KEY | esec decrypt prod -k  # private key on stdin",
	),
	"export": `Prints NAME=value lines that dotenv tools read back unchanged, without the public key.

` + examples(
		"esec export prod",
		"esec export .env.prod | fly secrets import",
	),
	"get": examples(
		"esec get prod DATABASE_URL",
		"esec get .env.prod API_TOKEN",
	),
	"run": `Runs the command with the file's values added to its environment, and returns its exit code. Supports dotenv, EJSON and TOML. TOML tables use uppercase double-underscore paths (database.host becomes DATABASE__HOST); arrays and dates are rejected.

` + examples(
		"esec run prod -- ./server",
		"esec run .env.dev -- npm test",
	),
}

// examples formats command lines as an indented block.
func examples(lines ...string) string {
	out := "Examples:\n\n"
	for _, l := range lines {
		out += "    " + l + "\n"
	}
	return out
}

// addDetails puts commandDetails on the command nodes.
func addDetails(app *kong.Application) {
	for _, n := range app.Children {
		if d, ok := commandDetails[n.Name]; ok {
			n.Detail = d
		}
	}
}

// helpArgs turns "help [command...]" into "[command...] --help", and no
// arguments into "--help", so both show help instead of an error.
func helpArgs(args []string) []string {
	if len(args) == 0 {
		return []string{"--help"}
	}
	if args[0] == "help" {
		return append(append([]string{}, args[1:]...), "--help")
	}
	return args
}

// vaultInstall says how to install esec-vault, which provides "esec vault".
const vaultInstall = "go install github.com/mscno/esec-vault/cmd/esec-vault@latest (or a release from https://github.com/mscno/esec-vault/releases)"

// printHelp is kong's help, and at the top level the commands that
// esec-<name> programs on PATH add (git-style), so "esec vault" shows up.
func printHelp(options kong.HelpOptions, ctx *kong.Context) error {
	if err := kong.DefaultHelpPrinter(options, ctx); err != nil {
		return err
	}
	if ctx.Selected() == nil {
		printExternal(ctx.Stdout)
	}
	return nil
}

func printExternal(w io.Writer) {
	found := externalCommands()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "More commands, from esec-<name> programs on PATH:")
	if !slices.Contains(found, "vault") {
		fmt.Fprintln(w, "  vault    Identity, backup and team sharing (not installed: "+vaultInstall+")")
	}
	for _, name := range found {
		about := ""
		if name == "vault" {
			about = `Identity, backup and team sharing; see "esec vault --help"`
		}
		fmt.Fprintf(w, "  %-8s %s\n", name, strings.TrimSpace(about))
	}
}

// externalCommands lists the esec-<name> executables on PATH.
func externalCommands() []string {
	var out []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name, ok := strings.CutPrefix(e.Name(), "esec-")
			name = strings.TrimSuffix(name, ".exe")
			// esec-vault-server is a server, not a command of esec.
			if !ok || name == "" || name == "vault-server" || builtinCommands[name] || slices.Contains(out, name) || strings.ContainsAny(name, ".") {
				continue
			}
			if _, err := exec.LookPath(e.Name()); err == nil {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// missingFile explains a secrets file that does not exist, with the secrets
// files that do.
func missingFile(name string) error {
	dir := filepath.Dir(name)
	base := filepath.Base(name)
	var here, sameEnv []string
	entries, _ := os.ReadDir(dir)
	suffix := envSuffix(base)
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !isSecretsFile(n) {
			continue
		}
		here = append(here, n)
		if suffix != "" && envSuffix(n) == suffix {
			sameEnv = append(sameEnv, n)
		}
	}
	where := "here"
	if dir != "." {
		where = "in " + dir
	}
	switch {
	case len(sameEnv) > 0:
		return fmt.Errorf("secrets file %s does not exist, but %s does: name that file, or pass --format %s", name, filepath.Join(dir, sameEnv[0]), strings.TrimPrefix(formatOf(sameEnv[0]), "."))
	case len(here) > 0:
		return fmt.Errorf("secrets file %s does not exist; secrets files %s: %s", name, where, strings.Join(here, ", "))
	default:
		return fmt.Errorf("secrets file %s does not exist, and there are no secrets files %s: run this where they are, or name the file", name, where)
	}
}

func isSecretsFile(name string) bool {
	if name == ".esec-keyring" || name == "esec.toml" {
		return false
	}
	return formatOf(name) != ""
}

// formatOf returns a secrets file name's format (".env"), or "".
func formatOf(name string) string {
	for _, f := range fileutils.ValidFormats() {
		rest, ok := strings.CutPrefix(name, string(f))
		if ok && (rest == "" || strings.HasPrefix(rest, ".")) {
			return string(f)
		}
	}
	return ""
}

// envSuffix returns a secrets file name's environment ("prod" for
// .env.prod), or "".
func envSuffix(name string) string {
	f := formatOf(name)
	if f == "" {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(name, f), ".")
}

// hints says what to do about a failed command, where the error cannot.
func hints(err error) []string {
	if h := hintText(err); h != "" {
		return []string{h}
	}
	var nf *esec.KeyNotFoundError
	if errors.As(err, &nf) {
		if nf.Guarded && nf.Sealed != "" {
			// No key esec could be given opens it: the error says the way.
			return nil
		}
		return []string{"give esec the private key in one of these ways:" +
			"\n  export " + nf.Name + "=<private key>" +
			"\n  add the line " + nf.Name + "=<private key> to .esec-keyring (never commit it)" +
			"\n  pass it on stdin with -k" +
			"\n  with esec vault: esec vault sync fetches the keys of shared projects; esec vault run <env> -- <command> uses them"}
	}
	return nil
}

// hintText returns a next step carried by err, if it has one.
func hintText(err error) string {
	for err != nil {
		if h, ok := err.(interface{ Hint() string }); ok && h.Hint() != "" {
			return h.Hint()
		}
		err = errors.Unwrap(err)
	}
	return ""
}
