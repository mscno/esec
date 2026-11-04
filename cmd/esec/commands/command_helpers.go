package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
	"golang.org/x/term"
)

// setupInteractive reports whether a wizard can run. Tests replace it.
var setupInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func parseEnvList(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if err := config.ValidateEnvironment(name); err != nil {
			return nil, err
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

func validateName(format, name string) error {
	f := &projectfile.File{Project: "acme/store", Files: projectfile.Files{Format: format, Name: name}}
	return f.Validate()
}

func derivedName(format, create, explicit string) (string, error) {
	if explicit != "" {
		if err := validateName(format, explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	name := strings.ReplaceAll(create, "{format}", strings.TrimPrefix(format, "."))
	if err := validateName(format, name); err != nil {
		return "", fmt.Errorf("filename pattern %q is not valid for %s: %w", name, format, err)
	}
	return name, nil
}

func skeleton(format, pub string) string {
	switch format {
	case "ejson":
		return "{\n  \"_ESEC_PUBLIC_KEY\": \"" + pub + "\"\n}\n"
	case "eyaml", "eyml":
		return "_ESEC_PUBLIC_KEY: " + pub + "\n"
	case "etoml":
		return "_ESEC_PUBLIC_KEY = \"" + pub + "\"\n"
	default:
		return "ESEC_PUBLIC_KEY=" + pub + "\n"
	}
}

func say(ctx *cliCtx, format string, args ...any) {
	if ctx != nil && ctx.Quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "esec: "+format+"\n", args...)
}
