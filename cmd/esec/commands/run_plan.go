package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/projectfile"
)

type runVariableSource struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type runPlan struct {
	Environment         string               `json:"environment"`
	File                string               `json:"file"`
	EnvironmentVariable string               `json:"environment_variable,omitempty"`
	PreserveEnv         []string             `json:"preserve_env"`
	Variables           []runVariableSource  `json:"variables"`
	Read                *esec.ReadInspection `json:"read"`
}

func (c *RunCmd) plan() (*runPlan, *esec.ReadTarget, error) {
	target, err := esec.ResolveRead(".", c.File, c.Format)
	if err != nil {
		var readErr *esec.ReadError
		if errors.As(err, &readErr) && readErr.Code == "environment_ambiguous" {
			return nil, nil, errors.New("ambiguous secrets files; pass an explicit file or --format")
		}
		return nil, nil, errors.New("cannot resolve secrets file or access metadata; use esec check")
	}
	p := &runPlan{Environment: target.Environment, File: target.Path, PreserveEnv: []string{}, Variables: []runVariableSource{}}
	if target.Root != "" {
		pf, err := projectfile.Load(target.Root)
		if err != nil {
			return nil, nil, err
		}
		if len(pf.Unknown()) > 0 {
			return nil, nil, errors.New("esec.toml contains unknown settings; fix typos or update Esec")
		}
		p.EnvironmentVariable = pf.Run.EnvironmentVariable
		p.PreserveEnv = append(p.PreserveEnv, pf.Env[target.Environment].Run.PreserveEnv...)
	}
	for _, names := range c.PreserveEnv {
		for _, name := range strings.Split(names, ",") {
			name = strings.TrimSpace(name)
			if err := projectfile.ValidateRunVariable(name); err != nil {
				return nil, nil, err
			}
			if !slices.Contains(p.PreserveEnv, name) {
				p.PreserveEnv = append(p.PreserveEnv, name)
			}
		}
	}
	if err := p.validateBinding(); err != nil {
		return nil, nil, err
	}
	// Names are obtained from ciphertext using the same flattening rules as run.
	vars, err := esec.EnvVars(target.Content, target.Format)
	if err != nil {
		return nil, nil, errors.New("cannot map this secrets file to environment variable names")
	}
	if _, exists := vars[p.EnvironmentVariable]; p.EnvironmentVariable != "" && exists {
		return nil, nil, errors.New("the environment binding is also in the secrets file; move it to public configuration")
	}
	for name := range vars {
		source := "secret_file"
		if _, exists := os.LookupEnv(name); exists && slices.Contains(p.PreserveEnv, name) {
			source = "inherited_override"
		}
		p.Variables = append(p.Variables, runVariableSource{Name: name, Source: source})
	}
	if p.EnvironmentVariable != "" {
		p.Variables = append(p.Variables, runVariableSource{Name: p.EnvironmentVariable, Source: "environment_binding"})
	}
	sort.Slice(p.Variables, func(i, j int) bool { return p.Variables[i].Name < p.Variables[j].Name })
	sort.Strings(p.PreserveEnv)
	p.Read = esec.InspectRead(target, esec.ReadOptions{KeyDir: c.KeyDir})
	return p, target, nil
}

func (p *runPlan) validateBinding() error {
	if p.EnvironmentVariable == "" {
		return nil
	}
	if p.Environment == "" {
		return errors.New("environment binding requires a named environment")
	}
	if slices.Contains(p.PreserveEnv, p.EnvironmentVariable) {
		return errors.New("--preserve-env cannot override the selected environment binding")
	}
	if value, exists := os.LookupEnv(p.EnvironmentVariable); exists && value != p.Environment {
		return fmt.Errorf("%s conflicts with the selected environment %q; unset it or select the matching environment", p.EnvironmentVariable, p.Environment)
	}
	return nil
}

func (p *runPlan) print(asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	fmt.Printf("Environment: %s\nFile: %s\nRoute: %s (availability unverified)\n", p.Environment, p.File, p.Read.Route)
	if p.EnvironmentVariable != "" {
		fmt.Printf("Binding: %s=%s\n", p.EnvironmentVariable, p.Environment)
	}
	for _, v := range p.Variables {
		fmt.Printf("%q: %s\n", v.Name, v.Source)
	}
	for _, blocker := range p.Read.Blockers {
		fmt.Printf("Blocker: %s\n", blocker.Code)
	}
	return nil
}

func readRunKey(fromStdin bool) (string, error) {
	if !fromStdin {
		return "", nil
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("could not read private key from stdin")
	}
	return strings.TrimSpace(string(data)), nil
}
