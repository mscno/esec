package stores

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/datastore"
)

const (
	projectKind            = "Project"
	projectUserSecretsKind = "ProjectUserSecrets"
)

// ProjectDataStore implements the ProjectStore interface using Google Cloud Datastore
type ProjectDataStore struct {
	client *datastore.Client
}

// NewProjectDataStore creates a new ProjectDataStore with the given client
func NewProjectDataStore(ctx context.Context, client *datastore.Client) (*ProjectDataStore, error) {
	return &ProjectDataStore{client: client}, nil
}

// Close closes the underlying datastore client
func (s *ProjectDataStore) Close() error {
	return s.client.Close()
}

// projectKey creates a datastore key for a project
func (s *ProjectDataStore) projectKey(orgRepo string) *datastore.Key {
	return datastore.NameKey(projectKind, orgRepo, nil)
}

// userSecretsKey creates a datastore key for project user secrets
func (s *ProjectDataStore) userSecretsKey(orgRepo string, userID string) *datastore.Key {
	// Use a composite key of project ID and user ID
	compositeKey := fmt.Sprintf("%s:%s", orgRepo, userID)
	return datastore.NameKey(projectUserSecretsKind, compositeKey, s.projectKey(orgRepo))
}

// CreateProject creates a new project in the datastore
func (s *ProjectDataStore) CreateProject(ctx context.Context, project Project) error {
	key := s.projectKey(project.OrgRepo)
	// Check if project already exists
	var existingProject Project
	err := s.client.Get(ctx, key, &existingProject)
	if err == nil {
		return ErrProjectExists
	}
	if !errors.Is(err, datastore.ErrNoSuchEntity) {
		return err // Some other error occurred
	}

	// Project does not exist, create it
	_, err = s.client.Put(ctx, key, &project)
	return err
}

// GetProject retrieves a project from the datastore
func (s *ProjectDataStore) GetProject(ctx context.Context, orgRepo string) (Project, error) {
	key := s.projectKey(orgRepo)
	var project Project
	err := s.client.Get(ctx, key, &project)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return Project{}, ErrProjectNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return project, nil
}

// UpdateProject updates a project in the datastore
func (s *ProjectDataStore) UpdateProject(ctx context.Context, orgRepo string, updateFn func(project Project) (Project, error)) error {
	key := s.projectKey(orgRepo)
	tx, err := s.client.NewTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() // Rollback if commit fails or anything goes wrong

	var project Project
	err = tx.Get(key, &project)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return ErrProjectNotFound
	}
	if err != nil {
		return err
	}

	updatedProject, err := updateFn(project)
	if err != nil {
		return err // Error from the update function itself
	}

	// Ensure OrgRepo hasn't changed
	if updatedProject.OrgRepo != orgRepo {
		return errors.New("cannot change OrgRepo during update")
	}

	_, err = tx.Put(key, &updatedProject)
	if err != nil {
		return err
	}

	_, err = tx.Commit()
	return err
}

// ListProjects lists all projects in the datastore
func (s *ProjectDataStore) ListProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	query := datastore.NewQuery(projectKind)
	_, err := s.client.GetAll(ctx, query, &projects)
	if err != nil {
		return nil, err
	}
	// If projects is nil (GetAll returns nil slice on no results), return empty slice
	if projects == nil {
		return []Project{}, nil
	}
	return projects, nil
}

// DeleteProject deletes a project and all its associated user secrets
func (s *ProjectDataStore) DeleteProject(ctx context.Context, orgRepo string) error {

	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return err
	}

	// First delete all user secrets for this project
	err = s.DeleteAllProjectUserSecrets(ctx, orgRepo)
	if err != nil {
		return fmt.Errorf("failed to delete project user secrets: %w", err)
	}

	// Then delete the project itself
	key := s.projectKey(orgRepo)
	err = s.client.Delete(ctx, key)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return ErrProjectNotFound
	}
	return err
}

// mapToSecretPairs converts a map[string]string to []SecretPair
func mapToSecretPairs(m map[string]string) []SecretPair {
	pairs := make([]SecretPair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, SecretPair{Key: k, Value: v})
	}
	return pairs
}

// secretPairsToMap converts []SecretPair to map[string]string
func secretPairsToMap(pairs []SecretPair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		m[pair.Key] = pair.Value
	}
	return m
}

// SetProjectUserSecrets sets secrets for a specific user in a project
func (s *ProjectDataStore) SetProjectUserSecrets(ctx context.Context, orgRepo string, userID string, secrets map[string]string) error {
	// Verify project exists first
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return err
	}

	key := s.userSecretsKey(orgRepo, userID)
	userSecrets := ProjectUserSecrets{
		ProjectID: orgRepo,
		UserID:    userID,
		Secrets:   mapToSecretPairs(secrets),
	}

	_, err = s.client.Put(ctx, key, &userSecrets)
	return err
}

// GetProjectUserSecrets gets secrets for a specific user in a project
func (s *ProjectDataStore) GetProjectUserSecrets(ctx context.Context, orgRepo string, userID string) (map[string]string, error) {
	// Verify project exists first
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return nil, err
	}

	key := s.userSecretsKey(orgRepo, userID)
	var userSecrets ProjectUserSecrets
	err = s.client.Get(ctx, key, &userSecrets)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return map[string]string{}, nil // Return empty map if not found
	}
	if err != nil {
		return nil, err
	}
	return secretPairsToMap(userSecrets.Secrets), nil
}

// GetAllProjectUserSecrets gets all user secrets for a project
func (s *ProjectDataStore) GetAllProjectUserSecrets(ctx context.Context, orgRepo string) (map[string]map[string]string, error) {
	// Verify project exists first
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return nil, err
	}

	// Query all user secrets for this project
	query := datastore.NewQuery(projectUserSecretsKind).Ancestor(s.projectKey(orgRepo))
	var userSecrets []ProjectUserSecrets
	_, err = s.client.GetAll(ctx, query, &userSecrets)
	if err != nil {
		return nil, err
	}

	// Build the result map
	result := make(map[string]map[string]string)
	for _, us := range userSecrets {
		result[us.UserID] = secretPairsToMap(us.Secrets)
	}
	return result, nil
}

// DeleteProjectUserSecrets deletes secrets for a specific user in a project
func (s *ProjectDataStore) DeleteProjectUserSecrets(ctx context.Context, orgRepo string, userID string) error {
	key := s.userSecretsKey(orgRepo, userID)
	return s.client.Delete(ctx, key)
}

// DeleteAllProjectUserSecrets deletes all user secrets for a project
func (s *ProjectDataStore) DeleteAllProjectUserSecrets(ctx context.Context, orgRepo string) error {
	// Query all user secrets for this project
	query := datastore.NewQuery(projectUserSecretsKind).Filter("project_id =", orgRepo).KeysOnly()
	keys, err := s.client.GetAll(ctx, query, nil)
	if err != nil {
		return err
	}

	// Delete all user secrets in batches if needed
	if len(keys) > 0 {
		const batchSize = 500 // Datastore has limits on batch operations
		for i := 0; i < len(keys); i += batchSize {
			end := i + batchSize
			if end > len(keys) {
				end = len(keys)
			}
			batch := keys[i:end]
			if err := s.client.DeleteMulti(ctx, batch); err != nil {
				return err
			}
		}
	}
	return nil
}

// Ensure ProjectDataStore implements ProjectStore
var _ ProjectStore = (*ProjectDataStore)(nil)
