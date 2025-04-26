package stores

import (
	"context"
	"errors"
)

type Project struct {
	OrgRepo string
	Admins  []string
	// Removed the Secrets field
}

// SecretPair represents a key-value pair for a secret
type SecretPair struct {
	Key   string `datastore:"key"`
	Value string `datastore:"value,noindex"`
}

// ProjectUserSecrets represents secrets for a specific user in a project
type ProjectUserSecrets struct {
	ProjectID string       `datastore:"project_id"` // OrgRepo
	UserID    string       `datastore:"user_id"`
	Secrets   []SecretPair `datastore:"secrets,noindex"`
}

type ProjectStore interface {
	CreateProject(ctx context.Context, project Project) error
	GetProject(ctx context.Context, orgRepo string) (Project, error)
	UpdateProject(ctx context.Context, orgRepo string, updateFn func(project Project) (Project, error)) error
	ListProjects(ctx context.Context) ([]Project, error)
	DeleteProject(ctx context.Context, orgRepo string) error

	// New methods for handling secrets
	SetProjectUserSecrets(ctx context.Context, orgRepo string, userID string, secrets map[string]string) error
	GetProjectUserSecrets(ctx context.Context, orgRepo string, userID string) (map[string]string, error)
	GetAllProjectUserSecrets(ctx context.Context, orgRepo string) (map[string]map[string]string, error)
	DeleteProjectUserSecrets(ctx context.Context, orgRepo string, userID string) error
	DeleteAllProjectUserSecrets(ctx context.Context, orgRepo string) error
}

var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")
