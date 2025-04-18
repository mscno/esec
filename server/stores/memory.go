package stores

import (
	"fmt"
	"sync"
)

type MemoryStore struct {
	mu       sync.RWMutex
	projects map[string]map[string]string            // key: org/repo
	perUser  map[string]map[string]map[string]string // org/repo -> user -> key -> value
	meta     map[string]*ProjectMeta                 // org/repo -> metadata (admins, etc.)
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		projects: make(map[string]map[string]string),
		perUser:  make(map[string]map[string]map[string]string),
		meta:     make(map[string]*ProjectMeta),
	}
}

func (m *MemoryStore) CreateProject(orgRepo string, adminID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.projects[orgRepo]; !exists {
		m.projects[orgRepo] = make(map[string]string)
		m.meta[orgRepo] = &ProjectMeta{Admins: []string{adminID}}
	}
	return nil
}

func (m *MemoryStore) ProjectExists(orgRepo string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.projects[orgRepo]
	return exists
}

func (m *MemoryStore) GetSecrets(orgRepo string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secrets, exists := m.projects[orgRepo]
	if !exists {
		return nil, fmt.Errorf("project not found")
	}
	copy := make(map[string]string, len(secrets))
	for k, v := range secrets {
		copy[k] = v
	}
	return copy, nil
}

func (m *MemoryStore) SetSecrets(orgRepo string, secrets map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.projects[orgRepo]; !exists {
		return fmt.Errorf("project not found")
	}
	for k, v := range secrets {
		m.projects[orgRepo][k] = v
	}
	return nil
}

func (m *MemoryStore) GetProjectAdmins(orgRepo string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	meta, exists := m.meta[orgRepo]
	if !exists || meta == nil {
		return nil, fmt.Errorf("project not found")
	}
	return append([]string{}, meta.Admins...), nil
}

func (m *MemoryStore) IsProjectAdmin(orgRepo string, githubID string) bool {
	admins, err := m.GetProjectAdmins(orgRepo)
	if err != nil {
		return false
	}
	for _, admin := range admins {
		if admin == githubID {
			return true
		}
	}
	return false
}

// GetPerUserSecrets returns the per-user secrets for a project
func (m *MemoryStore) GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secrets, exists := m.perUser[orgRepo]
	if !exists {
		return nil, fmt.Errorf("project not found")
	}
	copy := make(map[string]map[string]string, len(secrets))
	for user, kv := range secrets {
		userCopy := make(map[string]string, len(kv))
		for k, v := range kv {
			userCopy[k] = v
		}
		copy[user] = userCopy
	}
	return copy, nil
}

// SetPerUserSecrets sets the per-user secrets for a project
func (m *MemoryStore) SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.projects[orgRepo]; !exists {
		return fmt.Errorf("project not found")
	}
	perUserCopy := make(map[string]map[string]string, len(secrets))
	for user, kv := range secrets {
		userCopy := make(map[string]string, len(kv))
		for k, v := range kv {
			userCopy[k] = v
		}
		perUserCopy[user] = userCopy
	}
	m.perUser[orgRepo] = perUserCopy
	return nil
}
