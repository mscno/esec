package project

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const ProjectFileName = ".esec-project"
const ProjectKey = "ESEC_PROJECT"

var projectFormatRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

// ValidateOrgRepo checks if the project name conforms to the 'org/repo' format.
func ValidateOrgRepo(orgRepo string) error {
	if !projectFormatRegex.MatchString(orgRepo) {
		return fmt.Errorf("invalid project format: must be 'org/repo'")
	}
	return nil
}

// WriteProjectFile creates or overwrites the .esec-project file in the specified directory.
func WriteProjectFile(dir string, orgRepo string) error {
	if err := ValidateOrgRepo(orgRepo); err != nil {
		return err
	}
	filePath := filepath.Join(dir, ProjectFileName)
	content := fmt.Sprintf("%s=%s\n", ProjectKey, orgRepo)
	return os.WriteFile(filePath, []byte(content), 0644)
}

// ReadProjectFile reads the .esec-project file from the specified directory
// and returns the project name (org/repo).
func ReadProjectFile(dir string) (string, error) {
	filePath := filepath.Join(dir, ProjectFileName)
	file, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("project file '%s' not found in '%s'", ProjectFileName, dir)
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
