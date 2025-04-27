package stores

import (
	"context"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
	"sync"
)

type InMemoryProjectStore struct {
	mu          sync.RWMutex
	projects    map[model.OrgRepo]model.Project
	userSecrets map[model.OrgRepo]map[model.UserId]map[model.PrivateKeyName]string // map[orgRepo]map[userID]map[key]value
}

func NewInMemoryProjectStore() *InMemoryProjectStore {
	return &InMemoryProjectStore{
		projects:    make(map[model.OrgRepo]model.Project),
		userSecrets: make(map[model.OrgRepo]map[model.UserId]map[model.PrivateKeyName]string),
	}
}

func (s *InMemoryProjectStore) CreateProject(ctx context.Context, project model.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.projects[project.OrgRepo]; exists {
		return server.ErrProjectExists
	}
	s.projects[project.OrgRepo] = project
	// Initialize the secrets map for this project
	s.userSecrets[project.OrgRepo] = make(map[model.UserId]map[model.PrivateKeyName]string)
	return nil
}

func (s *InMemoryProjectStore) GetProject(ctx context.Context, orgRepo model.OrgRepo) (model.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[orgRepo]
	if !ok {
		return model.Project{}, server.ErrProjectNotFound
	}
	return p, nil
}

func (s *InMemoryProjectStore) UpdateProject(ctx context.Context, orgRepo model.OrgRepo, updateFn func(project model.Project) (model.Project, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	project, ok := s.projects[orgRepo]
	if !ok {
		return server.ErrProjectNotFound
	}

	project, err := updateFn(project)
	if err != nil {
		return err
	}
	s.projects[project.OrgRepo] = project
	return nil
}

func (s *InMemoryProjectStore) ListProjects(ctx context.Context) ([]model.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []model.Project
	for _, p := range s.projects {
		result = append(result, p)
	}
	return result, nil
}

func (s *InMemoryProjectStore) DeleteProject(ctx context.Context, orgRepo model.OrgRepo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[orgRepo]; !ok {
		return server.ErrProjectNotFound
	}
	delete(s.projects, orgRepo)
	// Also delete all user secrets for this project
	delete(s.userSecrets, orgRepo)
	return nil
}

func (s *InMemoryProjectStore) SetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userID model.UserId, secrets map[model.PrivateKeyName]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if project exists
	if _, ok := s.projects[orgRepo]; !ok {
		return server.ErrProjectNotFound
	}

	// Ensure project secrets map is initialized
	if _, ok := s.userSecrets[orgRepo]; !ok {
		s.userSecrets[orgRepo] = make(map[model.UserId]map[model.PrivateKeyName]string)
	}

	// Set the user's secrets
	secretsCopy := make(map[model.PrivateKeyName]string)
	for k, v := range secrets {
		secretsCopy[k] = v
	}
	s.userSecrets[orgRepo][userID] = secretsCopy
	return nil
}

func (s *InMemoryProjectStore) GetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userID model.UserId) (map[model.PrivateKeyName]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if project exists
	if _, ok := s.projects[orgRepo]; !ok {
		return nil, server.ErrProjectNotFound
	}

	// Check if project secrets map is initialized
	projectSecrets, ok := s.userSecrets[orgRepo]
	if !ok {
		return make(map[model.PrivateKeyName]string), nil
	}

	// Get user secrets
	userSecrets, ok := projectSecrets[userID]
	if !ok {
		return make(map[model.PrivateKeyName]string), nil
	}

	// Return a copy of the secrets to prevent mutations
	secretsCopy := make(map[model.PrivateKeyName]string)
	for k, v := range userSecrets {
		secretsCopy[k] = v
	}
	return secretsCopy, nil
}

func (s *InMemoryProjectStore) GetAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) (map[model.UserId]map[model.PrivateKeyName]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if project exists
	if _, ok := s.projects[orgRepo]; !ok {
		return nil, server.ErrProjectNotFound
	}

	// Check if project secrets map is initialized
	projectSecrets, ok := s.userSecrets[orgRepo]
	if !ok {
		return make(map[model.UserId]map[model.PrivateKeyName]string), nil
	}

	// Return a deep copy of all user secrets for this project
	result := make(map[model.UserId]map[model.PrivateKeyName]string)
	for userID, secrets := range projectSecrets {
		userSecretsCopy := make(map[model.PrivateKeyName]string)
		for k, v := range secrets {
			userSecretsCopy[k] = v
		}
		result[userID] = userSecretsCopy
	}
	return result, nil
}

func (s *InMemoryProjectStore) DeleteProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userID model.UserId) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if project exists
	if _, ok := s.projects[orgRepo]; !ok {
		return server.ErrProjectNotFound
	}

	// Check if project secrets map is initialized
	projectSecrets, ok := s.userSecrets[orgRepo]
	if !ok {
		return nil // Nothing to delete
	}

	// Delete user secrets
	delete(projectSecrets, userID)
	return nil
}

func (s *InMemoryProjectStore) DeleteAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if project exists
	if _, ok := s.projects[orgRepo]; !ok {
		return server.ErrProjectNotFound
	}

	// Clear all user secrets for this project
	s.userSecrets[orgRepo] = make(map[model.UserId]map[model.PrivateKeyName]string)
	return nil
}

// Ensure InMemoryProjectStore implements ProjectStore
var _ server.ProjectStore = (*InMemoryProjectStore)(nil)
