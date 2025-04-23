package server

import (
	"fmt"
	"regexp"
)

var projectFormat = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

// validateOrgRepo ensures the orgRepo string is in the correct org/repo format
func validateOrgRepo(orgRepo string) error {
	if !projectFormat.MatchString(orgRepo) {
		return fmt.Errorf("invalid project name, must be org/repo")
	}
	return nil
}
