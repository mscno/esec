package stores

import "errors"

type ProjectStore interface {
	CreateProject(orgRepo string, adminID string) error
	ProjectExists(orgRepo string) bool
	GetProjectAdmins(orgRepo string) ([]string, error)
	IsProjectAdmin(orgRepo string, githubID string) bool
	GetSecrets(orgRepo string) (map[string]string, error)
	SetSecrets(orgRepo string, secrets map[string]string) error
	GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error)
	SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error
}

var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")
