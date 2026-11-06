// Package workspace resolves explicit member stores without policy inheritance.
package workspace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mscno/esec/pkg/projectfile"
)

// Index is a validated public member index and its canonical root.
type Index struct {
	Root    string
	Members map[string]string
}

// Find searches upward for the nearest workspace, stopping at a Git boundary.
// Store manifests encountered on the way do not inherit workspace configuration.
func Find(dir string) (*Index, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	for {
		marker := filepath.Join(abs, projectfile.ProjectFileName)
		if info, err := os.Lstat(marker); err == nil && !info.Mode().IsRegular() {
			return nil, errors.New("esec.toml must be a regular file, not a symlink")
		}
		f, err := projectfile.Load(abs)
		if err == nil && f.Workspace != nil {
			if len(f.Unknown()) > 0 {
				return nil, errors.New("unknown workspace settings")
			}
			return &Index{Root: abs, Members: f.Workspace.Members}, nil
		}
		if err != nil && !errors.Is(err, projectfile.ErrNotFound) {
			return nil, errors.New("invalid esec.toml while locating workspace")
		}
		if _, err := os.Lstat(filepath.Join(abs, ".git")); !errors.Is(err, os.ErrNotExist) {
			break
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return nil, errors.New("no workspace index found in this repository")
}

// Names returns explicit member aliases in deterministic order.
func (i *Index) Names() []string {
	names := make([]string, 0, len(i.Members))
	for name := range i.Members {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Store returns a member's directory only after checking its filesystem boundary.
// Symlinks, nested repositories/stores, and nested workspaces are rejected.
func (i *Index) Store(name string) (string, error) {
	if err := (&projectfile.File{Workspace: &projectfile.Workspace{Members: i.Members}}).Validate(); err != nil {
		return "", err
	}
	rel, ok := i.Members[name]
	if !ok {
		return "", errors.New("unknown workspace member; choose an alias declared in workspace.members")
	}
	root := i.Root
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		root = filepath.Join(root, part)
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("member %s: missing directory or symlink in path", name)
		}
		if _, err := os.Lstat(filepath.Join(root, ".git")); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("member %s: nested repository boundary", name)
		}
		if root != filepath.Join(i.Root, filepath.Clean(rel)) {
			if _, err := os.Lstat(filepath.Join(root, projectfile.ProjectFileName)); !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("member %s: path crosses another store", name)
			}
		}
	}
	marker := filepath.Join(root, projectfile.ProjectFileName)
	directory, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("member %s: directory unavailable", name)
	}
	for alias, path := range i.Members {
		if alias == name {
			continue
		}
		other, err := os.Stat(filepath.Join(i.Root, path))
		if err == nil && os.SameFile(directory, other) {
			return "", errors.New("workspace members must select distinct physical store directories")
		}
	}
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("member %s: missing regular esec.toml", name)
	}
	f, err := projectfile.Load(root)
	if err != nil || f.Workspace != nil {
		return "", fmt.Errorf("member %s: invalid store manifest or nested workspace", name)
	}
	return root, nil
}
