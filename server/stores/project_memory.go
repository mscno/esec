package stores

import (
	"context"
	"sync"
)

type InMemoryProjectStore struct {
	mu       sync.RWMutex
	projects map[string]Project
}

func NewInMemoryProjectStore() *InMemoryProjectStore {
	return &InMemoryProjectStore{
		projects: make(map[string]Project),
	}
}

func (s *InMemoryProjectStore) CreateProject(ctx context.Context, project Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.projects[project.OrgRepo]; exists {
		return ErrProjectExists
	}
	s.projects[project.OrgRepo] = project
	return nil
}

func (s *InMemoryProjectStore) GetProject(ctx context.Context, orgRepo string) (Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[orgRepo]
	if !ok {
		return Project{}, ErrProjectNotFound
	}
	return p, nil
}

func (s *InMemoryProjectStore) UpdateProject(ctx context.Context, orgRepo string, updateFn func(project Project) (Project, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	project, ok := s.projects[orgRepo]
	if !ok {
		return ErrProjectNotFound
	}

	project, err := updateFn(project)
	if err != nil {
		return err
	}
	s.projects[project.OrgRepo] = project
	return nil
}

func (s *InMemoryProjectStore) ListProjects(ctx context.Context) ([]Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Project
	for _, p := range s.projects {
		result = append(result, p)
	}
	return result, nil
}

func (s *InMemoryProjectStore) DeleteProject(ctx context.Context, orgRepo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[orgRepo]; !ok {
		return ErrProjectNotFound
	}
	delete(s.projects, orgRepo)
	return nil
}

var _ NewProjectStore = (*InMemoryProjectStore)(nil)
