package projectfile

import (
	"errors"
	"maps"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrWorkspace prevents a workspace index from being used as a secrets store.
var ErrWorkspace = errors.New("this is a workspace index; select a store with --member NAME, or use --workspace for read-only checks")

// Workspace indexes independent stores. It never supplies keys or access policy.
type Workspace struct {
	Members map[string]string `toml:"members"`
}

func (f *File) validateWorkspace() error {
	if f.Project != "" || f.Files != (Files{}) || len(f.Env) != 0 || f.Run != (Run{}) || len(f.RecoveryRecipients) != 0 {
		return errors.New("a workspace index cannot also contain project, files, env, run or recovery settings")
	}
	if len(f.Workspace.Members) == 0 || len(f.Workspace.Members) > 256 {
		return errors.New("a workspace requires between 1 and 256 explicit members")
	}
	paths := []string{}
	for name, path := range f.Workspace.Members {
		if err := validateWorkspaceMember(name, path); err != nil {
			return err
		}
		clean := filepath.Clean(path)
		for _, previous := range paths {
			if clean == previous || strings.HasPrefix(clean, previous+string(filepath.Separator)) || strings.HasPrefix(previous, clean+string(filepath.Separator)) {
				return errors.New("member directories must be distinct and must not overlap")
			}
		}
		paths = append(paths, clean)
	}
	return nil
}

func validateWorkspaceMember(name, path string) error {
	if !regexp.MustCompile(`^[a-z][a-z0-9_-]*$`).MatchString(name) {
		return errors.New("member names must start with a lowercase letter and contain lowercase letters, digits, underscores or hyphens")
	}
	if !filepath.IsLocal(path) || strings.ContainsAny(path, "*?[]\\\x00\r\n") || strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || filepath.Clean(path) == "." {
		return errors.New("member paths must be explicit relative subdirectories within the workspace")
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." || strings.EqualFold(part, ".git") || strings.EqualFold(part, ".esec") {
			return errors.New("unsafe workspace member path")
		}
	}
	return nil
}

func sameWorkspace(a, b *Workspace) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return maps.Equal(a.Members, b.Members)
}
