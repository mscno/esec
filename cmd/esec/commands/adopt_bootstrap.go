package commands

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/config"
	"github.com/mscno/esec/pkg/projectfile"
)

// Bootstrap is deliberately in memory until the old file has been opened and
// its replacement verified. A failed read must not publish partial metadata.
func adoptionProject(t *esec.ReadTarget, project string) (*projectfile.File, error) {
	if t.Project != "" {
		if project != "" && project != t.Project {
			return nil, errors.New("--project differs from esec.toml")
		}
		return nil, nil
	}
	if project == "" {
		return nil, errors.New("no esec.toml; rerun esec adopt with --project org/repo to create it after successful migration")
	}
	if err := projectfile.ValidateOrgRepo(project); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if err := safeProjectPath(root, t.Path); err != nil {
		return nil, err
	}
	for dir := filepath.Dir(t.Path); dir != root; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("run esec adopt from inside the target repository")
		}
	}
	if err := rejectOrphanedAncestors(filepath.Dir(t.Path)); err != nil {
		return nil, err
	}
	name, err := adoptionFilename(root, t)
	if err != nil {
		return nil, err
	}
	pf := &projectfile.File{Project: project, Files: projectfile.Files{Format: strings.TrimPrefix(string(t.Format), "."), Name: name}}
	// Validate the inferred environment before opening credentials or writing seals.
	pf.Env = map[string]projectfile.Env{t.Environment: {Key: t.PublicKey}}
	if err := pf.Validate(); err != nil {
		return nil, err
	}
	t.Root, t.Project = root, project
	return pf, nil
}

func adoptionFilename(root string, t *esec.ReadTarget) (string, error) {
	cfg, err := config.LoadDir(root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, t.Path)
	if err != nil {
		return "", err
	}
	for _, pattern := range cfg.Files.Patterns {
		pattern = strings.ReplaceAll(pattern, "{format}", strings.TrimPrefix(string(t.Format), "."))
		name, err := config.Expand(pattern, t.Environment, strings.TrimPrefix(string(t.Format), "."))
		if err != nil {
			continue
		}
		if name == rel {
			return pattern, nil
		}
		if filepath.Base(pattern) == pattern && name == filepath.Base(rel) {
			return filepath.Join(filepath.Dir(rel), pattern), nil
		}
	}
	return "", errors.New("cannot infer a project filename pattern; create esec.toml with files.name before adoption")
}

// Existing seals may encode access restrictions lost with their metadata.
// Neither init nor bootstrap adoption may replace that metadata by guessing.
func rejectOrphanedAccess(root string) error {
	path := filepath.Join(root, ".esec")
	if err := safeProjectPath(root, path); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != ".mutation-lock" {
			return errors.New(".esec contains existing access data but esec.toml is missing; restore the original metadata before migrating")
		}
	}
	return nil
}

func rejectOrphanedAncestors(dir string) error {
	for {
		if err := rejectOrphanedAccess(dir); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func validateInitPlaintext(path, format string, data []byte) error {
	if bytes.Contains(data, []byte("ESEC[")) {
		return fmt.Errorf("%s may contain encrypted values; use esec adopt (add --project org/repo if esec.toml is missing); not changed", path)
	}
	if _, err := esec.ExtractPublicKey(data, esec.FileFormat("."+format)); err == nil {
		target, err := esec.ResolveRead(filepath.Dir(path), path, "")
		if err != nil {
			return err
		}
		if target.Standalone || target.Guard != "none" || target.Seal != "" {
			return fmt.Errorf("%s has existing access metadata; use esec adopt or restore its encrypted contents; not changed", path)
		}
	}
	return nil
}
