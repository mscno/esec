package stores

// Store abstracts project/secret storage (can be swapped for persistent implementations)
type Store interface {
	CreateProject(orgRepo string, adminID string) error
	ProjectExists(orgRepo string) bool
	GetSecrets(orgRepo string) (map[string]string, error)
	SetSecrets(orgRepo string, secrets map[string]string) error
	GetProjectAdmins(orgRepo string) ([]string, error)
	IsProjectAdmin(orgRepo string, githubID string) bool
	// Per-user secrets
	GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error)
	SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error
}
