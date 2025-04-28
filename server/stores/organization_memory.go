package stores

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
)

// organizationMemoryStore provides an in-memory implementation of OrganizationDatastore.
type organizationMemoryStore struct {
	mu    sync.RWMutex
	orgs  map[string]*model.Organization // Map key is Organization ID
	byName map[string]string             // Map name to ID for GetOrganizationByName lookup
}

// NewOrganizationMemoryStore creates a new in-memory organization store.
func NewOrganizationMemoryStore() server.OrganizationStore {
	return &organizationMemoryStore{
		orgs:  make(map[string]*model.Organization),
		byName: make(map[string]string),
	}
}

func (s *organizationMemoryStore) CreateOrganization(ctx context.Context, org *model.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.orgs[org.ID]; exists {
		return errors.New("organization with this ID already exists")
	}
	if id, exists := s.byName[org.Name]; exists {
		if _, ok := s.orgs[id]; ok {
			return errors.New("organization with this name already exists")
		}
	}

	if org.Type == "" {
		return errors.New("organization type cannot be empty")
	}
	if org.Type == model.OrganizationTypeTeam && org.OwnerGithubID == "" {
		return errors.New("team organization must have an owner")
	}

	now := time.Now()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = now
	}
	org.UpdatedAt = now

	newOrg := *org // Make a copy to store
	s.orgs[newOrg.ID] = &newOrg
	s.byName[newOrg.Name] = newOrg.ID
	return nil
}

func (s *organizationMemoryStore) GetOrganizationByID(ctx context.Context, id string) (*model.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	org, ok := s.orgs[id]
	if !ok {
		return nil, ErrOrganizationNotFound
	}
	// Return a copy to prevent modification outside the store
	retOrg := *org
	return &retOrg, nil
}

func (s *organizationMemoryStore) GetOrganizationByName(ctx context.Context, name string) (*model.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.byName[name]
	if !ok {
		return nil, ErrOrganizationNotFound
	}

	org, ok := s.orgs[id]
	if !ok {
		// This indicates an inconsistency, name exists but ID doesn't
		// Might happen if Delete isn't careful
		return nil, ErrOrganizationNotFound
	}

	retOrg := *org
	return &retOrg, nil
}

func (s *organizationMemoryStore) UpdateOrganization(ctx context.Context, org *model.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existingOrg, ok := s.orgs[org.ID]
	if !ok {
		return ErrOrganizationNotFound
	}

	if existingOrg.Type != org.Type {
		return errors.New("cannot change organization type")
	}
	if existingOrg.OwnerGithubID != org.OwnerGithubID {
		return errors.New("cannot change organization owner")
	}

	if existingOrg.Name != org.Name {
		if otherID, nameExists := s.byName[org.Name]; nameExists && otherID != org.ID {
			return errors.New("another organization with this name already exists")
		}
		// Update name mapping
		delete(s.byName, existingOrg.Name)
		s.byName[org.Name] = org.ID
	}

	org.UpdatedAt = time.Now()
	org.CreatedAt = existingOrg.CreatedAt
	org.Type = existingOrg.Type
	org.OwnerGithubID = existingOrg.OwnerGithubID

	newOrg := *org // Store a copy
	s.orgs[org.ID] = &newOrg
	return nil
}

func (s *organizationMemoryStore) DeleteOrganization(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if org, ok := s.orgs[id]; ok {
		delete(s.byName, org.Name)
		delete(s.orgs, id)
	}
	// No error if not found, as per interface spec
	return nil
}

func (s *organizationMemoryStore) ListOrganizations(ctx context.Context) ([]*model.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*model.Organization, 0, len(s.orgs))
	for _, org := range s.orgs {
		// Return copies
		retOrg := *org
		list = append(list, &retOrg)
	}

	// Sort by name for consistent ordering
	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	return list, nil
}

// Ensure implementation satisfies the interface.
var _ server.OrganizationStore = (*organizationMemoryStore)(nil)
