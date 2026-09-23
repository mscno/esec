// Package projectfile reads and writes .esec-project files.
//
// A .esec-project file is a committed, non-secret marker that associates a
// repository with an esec project identifier in "org/repo" form. Tooling uses
// it to locate project-scoped resources, e.g. keyrings in the global keyring
// store (~/.config/esec/keyrings/<org>_<repo>.keyring).
package projectfile

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProjectFileName is the name of the project marker file.
const ProjectFileName = ".esec-project"

// ProjectKey is the variable name inside the project file.
const ProjectKey = "ESEC_PROJECT"

var projectFormatRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$`)

// ErrNotFound is returned when no .esec-project file can be found.
var ErrNotFound = errors.New("project file not found")

// ValidateOrgRepo checks if the project identifier conforms to the project
// format: 'org/repo', optionally with path segments for monorepo subprojects
// ('org/repo/services/registry').
func ValidateOrgRepo(orgRepo string) error {
	if !projectFormatRegex.MatchString(orgRepo) {
		return fmt.Errorf("invalid project format: must be 'org/repo[/path...]'")
	}
	// Reject dot-only segments; they carry path semantics.
	for _, seg := range strings.Split(orgRepo, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("invalid project format: must be 'org/repo[/path...]'")
		}
	}
	return nil
}

// KeyringName converts a project identifier ("org/repo") into a flat file
// name ("org_repo.keyring") suitable for the global keyring store.
func KeyringName(orgRepo string) string {
	return strings.ReplaceAll(orgRepo, "/", "_") + ".keyring"
}

// WriteProjectFile creates or overwrites the .esec-project file in the given directory.
func WriteProjectFile(dir string, orgRepo string) error {
	if err := ValidateOrgRepo(orgRepo); err != nil {
		return err
	}
	content := fmt.Sprintf("%s=%s\n", ProjectKey, orgRepo)
	//nolint:gosec // the project file is committed and non-secret
	return os.WriteFile(filepath.Join(dir, ProjectFileName), []byte(content), 0644)
}

// ReadProjectFile reads the .esec-project file directly in dir and returns the
// project identifier. It returns ErrNotFound if the file does not exist.
func ReadProjectFile(dir string) (string, error) {
	file, err := os.Open(filepath.Join(dir, ProjectFileName)) //nolint:gosec // dir is caller-provided
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("failed to open project file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, ProjectKey+"=") {
			value := strings.TrimPrefix(line, ProjectKey+"=")
			if err := ValidateOrgRepo(value); err != nil {
				return "", fmt.Errorf("invalid project format in '%s': %w", ProjectFileName, err)
			}
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading project file: %w", err)
	}
	return "", fmt.Errorf("'%s' key not found in '%s'", ProjectKey, ProjectFileName)
}

// FindProjectFile searches dir and its parents for a .esec-project file,
// returning the project identifier and the path of the file found. The search
// never crosses a repository boundary: it stops after checking the directory
// containing .git. It returns ErrNotFound if no project file exists.
func FindProjectFile(dir string) (project string, path string, err error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve directory: %w", err)
	}
	for {
		project, err := ReadProjectFile(abs)
		if err == nil {
			return project, filepath.Join(abs, ProjectFileName), nil
		}
		if !errors.Is(err, ErrNotFound) {
			return "", "", err
		}
		// Never climb out of a repository: a project file above the git root
		// must not claim this repo.
		if _, gerr := os.Stat(filepath.Join(abs, ".git")); gerr == nil {
			return "", "", ErrNotFound
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", "", ErrNotFound
		}
		abs = parent
	}
}
