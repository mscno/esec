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

A secrets file holds a public key and encrypted values and can be committed. New environments use age-sealed keys in .esec/keys/: a local developer identity for dev/test/staging, YubiKey recipients for production/recovery, and explicitly selected deployment identities. No server or daemon is required. Legacy files still support ESEC_PRIVATE_KEY_<ENV> and .esec-keyring.

Commands take a filename or discover an environment across supported formats and naming patterns. Environment names match exactly: "prod" and "production" are different environments. Multiple matches fail; use --format or an explicit path. Preferences live in ~/.config/esec/config.toml.

    esec keygen                        # a key pair to start a file with
    esec setup                         # configure this machine
    esec init --project acme/api --env dev --yes
    esec encrypt prod                  # discover and encrypt the matching file
    esec decrypt prod                  # print it decrypted
    esec get prod DATABASE_URL         # print one value
    esec export .env.prod              # NAME=value lines
    esec run prod -- ./server          # run with the values as environment variables
    esec inspect prod                  # explain the read route without opening keys

Scripts and agents: output goes to stdout and messages to stderr; "esec help <command>" explains one. Exit codes: 0 done, 1 failed, 80 bad usage; run returns its command's code.`

// commandDetails are the explanations and examples "esec <command> --help"
// shows, by command path.
var commandDetails = map[string]string{
	"blob":       "Store exact file bytes as versioned base64 inside an encrypted value, using the environment's existing recipients and rotation. --create adds a simple top-level key in any supported format. Imports never delete the source. get prints exact bytes or creates a new 0600 file with --out, refusing existing paths. run exposes only selected file paths in child variables, in a 0700 temporary directory; files are removed after exit, failure, SIGINT or SIGTERM. Disk output requires Unix permissions.\n\n" + examples("esec blob set production APPLE_P8 --create --from AuthKey.p8", "esec blob set production GOOGLE_JSON --create --stdin < service-account.json", "esec blob get production APPLE_P8 --out /secure/restored.p8", "esec blob run production --file GOOGLE_APPLICATION_CREDENTIALS=GOOGLE_JSON -- ./submit"),
	"check":      "Check every declared environment without decrypting or contacting a credential store. Exit 2 means findings. This validates ciphertext syntax and public metadata, not authenticity or whether a recipient can decrypt. Values and parser source lines are never printed.\n\n" + examples("esec check --ci", "esec check --json"),
	"set":        "Prompt twice without echoing, or read exact bytes from stdin. Only ciphertext is written; concurrent changes abort the save. Encryption uses the public key and does not require a private identity. Use --create for a new simple top-level key in any supported format.\n\n" + examples("esec set dev DATABASE_URL", "esec set production API_TOKEN --create --stdin < /secure/new-token"),
	"diff":       "Compare variable names and presence across exact environments. Never decrypts or compares values; differences are informational.\n\n" + examples("esec diff dev test production --keys-only", "esec diff dev production --json"),
	"recovery":   "Recovery phrases stay offline. Creation and import register only a public default for new dev and production environments; esec.toml remains authoritative afterward. All secret input uses a hidden controlling terminal. Optional passphrases are part of identity derivation, not a removable file password.\n\n" + examples("esec recovery create", "esec recovery import", "esec recovery verify production", "esec decrypt production --recovery", "esec apply --recovery"),
	"plan":       "Preview public recipient changes and an approval hash without opening any key.\n\n" + examples("esec plan", "esec plan --env dev,test --json"),
	"apply":      "Apply esec.toml recipient changes after confirmation. New access rotates environment keys. Production, removals, and untracked generations require stronger approval. All environments are prepared before any active ciphertext is changed.\n\n" + examples("esec apply", "esec apply --env dev,test", "esec apply --yes --plan-hash REVIEWED_HASH"),
	"status":     "Check desired access against the applied encrypted key generations. --check exits 2 for drift, creation, or legacy migration; invalid configuration exits 1.\n\n" + examples("esec status", "esec status --check", "esec status --json"),
	"files":      "Lists file paths, environments and key names without decrypting values.\n\n" + examples("esec files --dir . --json"),
	"secrets":    "Structured local document operations for native editors. Reads never contact a broker. Updates accept revision, key, value and create in JSON stdin.\n\n" + examples("esec secrets show --file .env.dev --json", "esec secrets update --file .env.dev"),
	"init":       "Creates age-sealed environments without a server. Dev includes your developer and recovery recipients; production excludes the developer identity.\n\n" + examples("esec init --project acme/store --env dev,production --yes", "esec init --project acme/store --env dev,test --format etoml --yes", "esec init --project acme/store --env dev,test --format ejson --yes", "esec init --env test --encrypt-existing --yes"),
	"identity":   "Creates a new software identity for a deployment or offline recovery. Use identity list to display configured public recipients. Creation prints only its public recipient and stores the private key in a new 0600 file. It is not automatically granted access or loaded locally.\n\n" + examples("esec identity list", "esec identity create --out /secure/deployment.age"),
	"recipients": "Lists desired recipients or confirms and rotates the environment key when they change. Unapplied TOML edits must first go through plan/apply. An added machine recipient can decrypt without hardware touch. Removed recipients retain access to older ciphertext and previously copied values.\n\n" + examples("esec recipients production", "esec recipients production --add age1..."),
	"rotate":     "Creates a fresh environment key, reseals it to the existing recipients, and re-encrypts the file. Old encrypted key generations remain for historical recovery.\n\n" + examples("esec rotate dev"),
	"adopt":      "Migrates a legacy environment by rotating its key and sealing the new key to configured standalone recipients. Legacy guarded files require an explicit age identity or recovered public-key-addressed credential. Old keys, seals and recovery paths are preserved.\n\n" + examples("esec adopt dev", "esec adopt production --machine-recipient age1..."),
	"repair":     "Completes an interrupted encrypted write using its local ciphertext journal. Does not retrieve keys or contact a server.\n\n" + examples("esec repair"),
	"inspect": `Resolves the same exact file, environment and protection as decrypt and run. Shows public metadata only: no secret-store entries are read, no seal opens, no hardware or approval is requested. Unknown availability stays unverified.

Examples:
    esec inspect production
    esec inspect .env.production --json
`,
	"setup": `Configures this machine's age identity files and default public recipients. Creates a software development identity when requested; a YubiKey provides production access and dev recovery. No project, server login, or daemon is created. YubiKey slots must require touch every time.

` + examples(
		"esec setup",
		"esec setup --generate-dev --yes",
		"esec setup --generate-dev --yubikey-recipient age1yubikey1... --yes",
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

// printHelp lists supported external editor integrations alongside builtins.
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
	if len(found) == 0 {
		return
	}
	fmt.Fprintln(w, "\nMore commands, from esec-<name> programs on PATH:")
	for _, name := range found {
		fmt.Fprintf(w, "  %s\n", name)
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
			// Never advertise retired service commands.
			if !ok || name == "" || retiredCommand(name) || builtinCommands[name] || slices.Contains(out, name) || strings.ContainsAny(name, ".") {
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
			"\n  pass it on stdin with -k"}
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
