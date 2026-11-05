package projectfile

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Run configures opt-in environment selection for esec run.
type Run struct {
	EnvironmentVariable string `toml:"environment_variable,omitempty"`
}

// EnvRun declares inherited overrides for a development environment.
type EnvRun struct {
	PreserveEnv []string `toml:"preserve_env,omitempty"`
}

var runVariable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateRunVariable excludes credential selectors and process loader controls.
func ValidateRunVariable(name string) error {
	if !runVariable.MatchString(name) || strings.HasPrefix(name, "ESEC_") || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") || name == "PATH" || name == "HOME" || name == "_ESEC_PUBLIC_KEY" {
		return errors.New("run settings require a variable name other than Esec credentials or process loader controls")
	}
	return nil
}

func validateEnvRun(name string, e Env, binding string) error {
	parts := strings.Split(name, ".")
	last := parts[len(parts)-1]
	if len(e.Run.PreserveEnv) > 0 && (e.Access == "production" || e.GuardLevel() != GuardNone || last == "production" || last == "prod" || last == "staging") {
		return fmt.Errorf("%s: inherited overrides must be explicit --preserve-env flags for staging, production, or guarded environments", name)
	}
	seen := map[string]bool{}
	for _, v := range e.Run.PreserveEnv {
		if err := ValidateRunVariable(v); err != nil {
			return err
		}
		if v == binding || seen[v] {
			return fmt.Errorf("%s: duplicate override or override of the environment binding", name)
		}
		seen[v] = true
	}
	return nil
}
