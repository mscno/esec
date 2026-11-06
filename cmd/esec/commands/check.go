package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/fileutils"
	"github.com/mscno/esec/pkg/projectfile"
	"github.com/mscno/esec/pkg/seal"
	"github.com/mscno/esec/pkg/secretfile"
)

// CheckCmd inspects declared environments without opening private credentials.
type CheckCmd struct {
	Workspace bool   `help:"Check every declared workspace member without opening keys"`
	Dir       string `default:"." type:"path" help:"Project directory"`
	CI        bool   `help:"Use non-interactive checks with exit 2 for findings (never opens keys)"`
	JSON      bool   `help:"Print findings as JSON without values"`
}

type checkFinding struct {
	Environment string   `json:"environment,omitempty"`
	Code        string   `json:"code"`
	Keys        []string `json:"keys,omitempty"`
}
type checkReport struct {
	Project      string         `json:"project"`
	Environments int            `json:"environments"`
	Findings     []checkFinding `json:"findings"`
}

// Run prints public diagnostics. Parsing failures never echo source lines.
func (c *CheckCmd) Run(_ *cliCtx) error {
	if c.Workspace {
		return reportWorkspace(c.Dir, "check", "", c.JSON, true)
	}
	report := checkProject(c.Dir)
	if c.JSON {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else {
		for _, f := range report.Findings {
			fmt.Printf("%q: %s", f.Environment, f.Code)
			for _, k := range f.Keys {
				fmt.Printf(" %q", k)
			}
			fmt.Println()
		}
		if len(report.Findings) == 0 {
			fmt.Printf("Checked %d environments: ciphertext and public access metadata are consistent.\n", report.Environments)
		}
	}
	if len(report.Findings) > 0 {
		return &ExitError{Code: 2}
	}
	return nil
}

func checkProject(dir string) checkReport {
	r := checkReport{Findings: []checkFinding{}}
	add := func(env, code string, keys ...string) {
		r.Findings = append(r.Findings, checkFinding{Environment: env, Code: code, Keys: keys})
	}
	pf, marker, err := projectfile.Find(dir)
	if err != nil {
		add("", "project_missing_or_invalid")
		return r
	}
	root := filepath.Dir(marker)
	r.Project, r.Environments = pf.Project, len(pf.Env)
	if len(pf.Unknown()) > 0 {
		add("", "unknown_project_settings", pf.Unknown()...)
	}
	if len(pf.Env) == 0 {
		add("", "no_managed_environments")
	}
	if _, err := os.Stat(filepath.Join(root, ".esec", "pending")); !errors.Is(err, os.ErrNotExist) {
		add("", "pending_write_requires_repair")
	}
	for _, env := range pf.Envs() {
		path, format, err := fileutils.Resolve(root, env, "")
		if err != nil {
			add(env, "file_missing_or_ambiguous")
			continue
		}
		if err := safeProjectPath(root, path); err != nil {
			add(env, "unsafe_file_path")
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // resolved managed file within the project
		if err != nil {
			add(env, "file_unreadable")
			continue
		}
		file, err := secretfile.Parse(path, data)
		if err != nil {
			add(env, "file_invalid")
			continue
		}
		if len(file.Plain) > 0 {
			add(env, "plaintext_values", file.Plain...)
		}
		if err := secretfile.ValidateCiphertext(data, format); err != nil {
			add(env, "malformed_ciphertext")
		}
		target, err := esec.ResolveRead(root, path, "")
		if err != nil {
			add(env, "access_metadata_invalid")
			continue
		}
		if !target.Standalone {
			add(env, "legacy_environment_requires_adoption")
			continue
		}
		if target.PolicyStatus != "current" {
			add(env, "access_"+target.PolicyStatus)
		}
		sealed, err := os.ReadFile(target.Seal)
		if err != nil || (target.AppliedPolicy != nil && seal.Hash(sealed) != target.AppliedPolicy.SealHash) {
			add(env, "sealed_key_missing_or_changed")
		}
	}
	plan, err := buildAccessPlan(root, "")
	if err != nil {
		add("", "project_access_policy_invalid")
	} else if plan.changed() {
		add("", "access_changes_pending")
	}
	return r
}
