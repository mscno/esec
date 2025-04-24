package stores

// MemoryStore implements ProjectStore interface in-memory (for testing/dev)
type MemoryStore struct {
	projects       map[string]*projectData
	perUserSecrets map[string]map[string]map[string]string // orgRepo -> githubID -> key -> value
}

type projectData struct {
	Admins  []string
	Secrets map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		projects:       make(map[string]*projectData),
		perUserSecrets: make(map[string]map[string]map[string]string),
	}
}

func (m *MemoryStore) CreateProject(orgRepo string, adminID string) error {
	if _, exists := m.projects[orgRepo]; exists {
		return ErrProjectExists
	}
	m.projects[orgRepo] = &projectData{
		Admins:  []string{adminID},
		Secrets: map[string]string{},
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

func (m *MemoryStore) GetSecrets(orgRepo string) (map[string]string, error) {
	p, ok := m.projects[orgRepo]
	if !ok {
		return nil, ErrProjectNotFound
	}
	return p.Secrets, nil
}

func (m *MemoryStore) SetSecrets(orgRepo string, secrets map[string]string) error {
	p, ok := m.projects[orgRepo]
	if !ok {
		return ErrProjectNotFound
	}
	p.Secrets = secrets
	return nil
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
