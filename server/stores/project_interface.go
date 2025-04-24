package stores

import (
	"context"
	"errors"
)

type Project struct {
	OrgRepo string
	Admins  []string
	Secrets map[string]map[string]string
}

type ProjectStore interface {
	CreateProject(orgRepo string, adminID string) error
	ProjectExists(orgRepo string) bool
	GetProjectAdmins(orgRepo string) ([]string, error)
	IsProjectAdmin(orgRepo string, githubID string) bool
	GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error)
	SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error
}

type NewProjectStore interface {
	CreateProject(ctx context.Context, project Project) error
	GetProject(ctx context.Context, orgRepo string) (Project, error)
	UpdateProject(ctx context.Context, orgRepo string, updateFn func(project Project) (Project, error)) error
	ListProjects(ctx context.Context) ([]Project, error)
	DeleteProject(ctx context.Context, orgRepo string) error
}

var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")
