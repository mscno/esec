package commands

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/joho/godotenv"
)

// ExportCmd decrypts a secrets file and prints its values as dotenv lines.
type ExportCmd struct {
	File         string `arg:"" help:"File or Environment to export" default:""`
	Format       string `help:"File format (ejson, env)" default:".ejson" short:"f" env:"ESEC_FORMAT"`
	KeyFromStdin bool   `help:"Read the key from stdin" short:"k"`
	KeyDir       string `help:"Directory containing the '.esec-keyring' file" default:"." short:"d" env:"ESEC_KEY_DIR"`
}

// Run executes the export command.
func (c *ExportCmd) Run(ctx *cliCtx) error {
	vars, _, err := decryptEnvVars(ctx, c.File, c.Format, c.KeyDir, c.KeyFromStdin)
	if err != nil {
		return err
	}
	return writeDotenv(os.Stdout, vars)
}

// writeDotenv writes vars as NAME=value lines, sorted by name. It writes
// nothing if any value cannot be written.
func writeDotenv(w io.Writer, vars map[string]string) error {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		value, err := dotenvValue(name, vars[name])
		if err != nil {
			return err
		}
		b.WriteString(name + "=" + value + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// dotenvValue returns the first form of value that dotenv parsers (esec run,
// godotenv, gh secret set -f) read back unchanged:
//
//   - bare, when it has only plain characters;
//   - single quotes, which are literal, when it has no quote, backslash, line
//     break or '#';
//   - double quotes with \\, \", \n, \r and \$ escaped;
//   - single quotes when it has a '#';
//   - bare, as a last resort (bare values have no escapes).
//
// Bare and single-quoted values, and double-quoted values that need no
// escapes, also import unchanged with fly secrets import. Each form is
// checked by parsing it back, because godotenv cannot represent every value
// (for example a value with a line break that ends in a double quote).
func dotenvValue(name, value string) (string, error) {
	var candidates []string
	if isPlainDotenv(value) {
		candidates = append(candidates, value)
	}
	if !strings.ContainsAny(value, "'\\\n\r#") {
		candidates = append(candidates, "'"+value+"'")
	}
	candidates = append(candidates, `"`+dotenvEscaper.Replace(value)+`"`)
	if !strings.ContainsAny(value, "'\n\r") {
		candidates = append(candidates, "'"+value+"'")
	}
	candidates = append(candidates, value)
	for _, c := range candidates {
		parsed, err := godotenv.Unmarshal(name + "=" + c)
		if err == nil && len(parsed) == 1 && parsed[name] == value {
			return c, nil
		}
	}
	return "", fmt.Errorf("the value of %s cannot be written as a dotenv line; use esec get or esec run instead", name)
}

var dotenvEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`)

// isPlainDotenv reports whether value can be written without quotes: letters,
// digits and punctuation that no dotenv parser treats specially.
func isPlainDotenv(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_-.,:/+=@%~^*!?", r):
		default:
			return false
		}
	}
	return true
}
