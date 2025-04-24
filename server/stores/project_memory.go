package stores

// MemoryStore implements ProjectStore interface in-memory (for testing/dev)
type MemoryStore struct {
	projects       map[string]*Project
	perUserSecrets map[string]map[string]map[string]string // orgRepo -> githubID -> key -> value
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		projects:       make(map[string]*Project),
		perUserSecrets: make(map[string]map[string]map[string]string),
	}
}

func (m *MemoryStore) CreateProject(orgRepo string, adminID string) error {
	if _, exists := m.projects[orgRepo]; exists {
		return ErrProjectExists
	}
	m.projects[orgRepo] = &Project{
		Admins: []string{adminID},
	}
	return nil
}

func (m *MemoryStore) ProjectExists(orgRepo string) bool {
	_, ok := m.projects[orgRepo]
	return ok
}

func (m *MemoryStore) GetProjectAdmins(orgRepo string) ([]string, error) {
	p, ok := m.projects[orgRepo]
	if !ok {
		return nil, ErrProjectNotFound
	}
	return p.Admins, nil
}

func (m *MemoryStore) IsProjectAdmin(orgRepo string, githubID string) bool {
	p, ok := m.projects[orgRepo]
	if !ok {
		return false
	}
	for _, admin := range p.Admins {
		if admin == githubID {
			return true
		}
	}
	return false
}

func (m *MemoryStore) GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error) {
	pu, ok := m.perUserSecrets[orgRepo]
	if !ok {
		return nil, ErrProjectNotFound
	}
	result := make(map[string]map[string]string)
	for k, v := range pu {
		result[k] = v
	}
	return result, nil
}

func (m *MemoryStore) SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error {
	if _, ok := m.projects[orgRepo]; !ok {
		return ErrProjectNotFound
	}
	m.perUserSecrets[orgRepo] = secrets
	return nil
}

var _ ProjectStore = (*MemoryStore)(nil)
