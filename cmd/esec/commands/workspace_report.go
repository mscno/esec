package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/mscno/esec/pkg/secretfile"
	"github.com/mscno/esec/pkg/workspace"
)

type workspaceMemberReport struct {
	Member string            `json:"member"`
	Path   string            `json:"path"`
	Error  string            `json:"error,omitempty"`
	Check  *checkReport      `json:"check,omitempty"`
	Plan   *AccessPlan       `json:"plan,omitempty"`
	Files  []secretfile.File `json:"files,omitempty"`
}

type workspaceReport struct {
	Workspace string                  `json:"workspace"`
	Members   []workspaceMemberReport `json:"members"`
}

func reportWorkspace(dir, operation, selection string, asJSON, check bool) error {
	i, err := workspace.Find(dir)
	if err != nil {
		return err
	}
	report := workspaceReport{Workspace: i.Root, Members: []workspaceMemberReport{}}
	failed, changed := false, false
	for _, name := range i.Names() {
		item := workspaceMemberReport{Member: name, Path: filepath.Join(i.Root, i.Members[name])}
		root, err := i.Store(name)
		if err != nil {
			item.Error = "member_missing_or_invalid"
		} else {
			switch operation {
			case "check":
				r := checkProject(root)
				item.Check = &r
				changed = changed || len(r.Findings) > 0
			case "plan", "status":
				p, err := buildAccessPlan(root, selection)
				if err != nil {
					item.Error = "member_plan_failed"
				} else {
					item.Plan = p
					changed = changed || p.changed()
				}
			case "files":
				files, err := secretfile.Scan(root)
				if err != nil {
					item.Error = "member_scan_failed"
				} else {
					item.Files = slices.DeleteFunc(files, func(f secretfile.File) bool { return f.Root != root })
				}
			}
		}
		failed = failed || item.Error != ""
		report.Members = append(report.Members, item)
	}
	if err := printWorkspaceReport(report, asJSON); err != nil {
		return err
	}

	if failed {
		if operation == "check" {
			return &ExitError{Code: 2}
		}
		return &ExitError{Code: 1}
	}
	if check && changed {
		return &ExitError{Code: 2}
	}
	return nil
}

func printWorkspaceReport(report workspaceReport, asJSON bool) error {
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else {
		for _, member := range report.Members {
			fmt.Printf("Member: %s (%s)\n", member.Member, member.Path)
			switch {
			case member.Error != "":
				fmt.Println("  " + member.Error)
			case member.Plan != nil:
				if err := printAccessPlan(member.Plan, false); err != nil {
					return err
				}
				fmt.Printf("Apply only this member: esec --member %s apply --plan-hash %s\n", member.Member, member.Plan.Hash)
			case member.Check != nil:
				for _, finding := range member.Check.Findings {
					fmt.Printf("  %q: %s\n", finding.Environment, finding.Code)
				}
				if len(member.Check.Findings) == 0 {
					fmt.Printf("  Checked %d environments.\n", member.Check.Environments)
				}
			}
		}
	}
	return nil
}
