package stores

import (
	"context"
	"errors"
	"fmt"

	"log/slog"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
)

const organizationKind = "Organization"

// OrganizationDataStore implements server.OrganizationStore using Google Cloud Datastore.
type OrganizationDataStore struct {
	client *datastore.Client
	logger *slog.Logger
}

// NewOrganizationDataStore creates a new datastore-backed organization store.
func NewOrganizationDataStore(logger *slog.Logger, client *datastore.Client) server.OrganizationStore {
	return &OrganizationDataStore{client: client, logger: logger}
}

// organizationKey creates a datastore key for an organization.
func (s *OrganizationDataStore) organizationKey(id string) *datastore.Key {
	return datastore.NameKey(organizationKind, id, nil)
}

func (s *OrganizationDataStore) CreateOrganization(ctx context.Context, org *model.Organization) error {
	key := s.organizationKey(org.ID)

	// Check if org with this ID already exists
	var existing model.Organization
	err := s.client.Get(ctx, key, &existing)
	if err == nil {
		return errors.New("organization with this ID already exists")
	}
	if !errors.Is(err, datastore.ErrNoSuchEntity) {
		return fmt.Errorf("failed to check for existing organization by ID: %w", err)
	}

	// Check if org with this Name already exists (using query)
	q := datastore.NewQuery(organizationKind).Filter("Name =", org.Name).Limit(1).KeysOnly()
	keys, err := s.client.GetAll(ctx, q, nil)
	if err != nil {
		return fmt.Errorf("failed to query for existing organization by name: %w", err)
	}
	if len(keys) > 0 {
		return errors.New("organization with this name already exists")
	}

	now := time.Now()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = now
	}
	org.UpdatedAt = now

	_, err = s.client.Put(ctx, key, org)
	if err != nil {
		return fmt.Errorf("failed to put organization: %w", err)
	}
	return nil
}

func (s *OrganizationDataStore) GetOrganizationByID(ctx context.Context, id string) (*model.Organization, error) {
	key := s.organizationKey(id)
	var org model.Organization
	err := s.client.Get(ctx, key, &org)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, server.ErrOrganizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization by ID: %w", err)
	}
	return &org, nil
}

func (s *OrganizationDataStore) GetOrganizationByName(ctx context.Context, name string) (*model.Organization, error) {
	q := datastore.NewQuery(organizationKind).Filter("Name =", name).Limit(1)
	var orgs []*model.Organization
	_, err := s.client.GetAll(ctx, q, &orgs)
	if err != nil {
		return nil, fmt.Errorf("failed to query organization by name: %w", err)
	}
	if len(orgs) == 0 {
		return nil, server.ErrOrganizationNotFound
	}
	return orgs[0], nil
}

func (s *OrganizationDataStore) UpdateOrganization(ctx context.Context, org *model.Organization) error {
	key := s.organizationKey(org.ID)

	tx, err := s.client.NewTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback() // Rollback if commit fails

	var existingOrg model.Organization
	if err := tx.Get(key, &existingOrg); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return server.ErrOrganizationNotFound
		}
		return fmt.Errorf("failed to get existing organization for update: %w", err)
	}

	// Check for name conflict if name is changing
	if existingOrg.Name != org.Name {
		q := datastore.NewQuery(organizationKind).Filter("Name =", org.Name).Limit(1).KeysOnly()
		keys, err := s.client.GetAll(ctx, q, nil) // Use client directly for query, doesn't need tx
		if err != nil {
			return fmt.Errorf("failed to query for name conflict: %w", err)
		}
		if len(keys) > 0 && keys[0].Name != org.ID { // Ensure the found key isn't the org itself
			return errors.New("another organization with this name already exists")
		}
	}

	// Preserve original CreatedAt, Type, OwnerGithubID
	org.CreatedAt = existingOrg.CreatedAt
	org.Type = existingOrg.Type
	org.OwnerGithubID = existingOrg.OwnerGithubID
	org.UpdatedAt = time.Now()

	_, err = tx.Put(key, org)
	if err != nil {
		return fmt.Errorf("failed to put updated organization: %w", err)
	}

	if _, err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *OrganizationDataStore) DeleteOrganization(ctx context.Context, id string) error {
	key := s.organizationKey(id)
	// It's okay if the org doesn't exist, Delete is idempotent in datastore
	err := s.client.Delete(ctx, key)
	if err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	return nil // No error if not found or deleted successfully
}

func (s *OrganizationDataStore) ListOrganizations(ctx context.Context) ([]*model.Organization, error) {
	var orgs []*model.Organization
	q := datastore.NewQuery(organizationKind).Order("Name") // Sort by name
	keys, err := s.client.GetAll(ctx, q, &orgs)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	_ = keys // keys might be useful later

	if orgs == nil {
		return []*model.Organization{}, nil // Return empty slice, not nil
	}
	return orgs, nil
}

// Ensure implementation satisfies the server interface.
var _ server.OrganizationStore = (*OrganizationDataStore)(nil)
