package stores

import (
	"context"
	"errors"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/pkg/cloudmodel"
	"github.com/mscno/esec/server"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupProjectDataStore sets up the Datastore emulator connection for project tests.
func setupProjectDataStore(t *testing.T) (*ProjectDataStore, context.Context) {
	t.Helper()
	ctx := context.Background()
	godotenv.Load("../../.env.test")
	// Use a unique project ID for testing to avoid conflicts
	// The actual project ID doesn't matter when using the emulator
	projectID := os.Getenv("TEST_DATASTORE_PROJECT")
	client, err := datastore.NewClientWithDatabase(ctx, projectID, "esec-test")
	assert.NoError(t, err)
	store := NewProjectDataStore(ctx, client)

	// Clear all data before each test run
	q := datastore.NewQuery(projectKind).KeysOnly()
	keys, err := store.client.GetAll(ctx, q, nil)
	if err == nil && len(keys) > 0 {
		_ = store.client.DeleteMulti(ctx, keys) // Ignore error during cleanup
	}

	t.Cleanup(func() {
		_ = store.Close() // Ensure client is closed after test
	})

	return store, ctx
}

func TestProjectDataStore_CreateProject(t *testing.T) {
	store, ctx := setupProjectDataStore(t)

	project := cloudmodel.Project{
		OrgRepo: "org/repo1",
	}

	// Test successful creation
	err := store.CreateProject(ctx, project)
	assert.NoError(t, err)

	// Test creating existing project
	err = store.CreateProject(ctx, project)
	assert.ErrorIs(t, err, server.ErrProjectExists)
}

func TestProjectDataStore_GetProject(t *testing.T) {
	store, ctx := setupProjectDataStore(t)

	project := cloudmodel.Project{
		OrgRepo: "org/repo2",
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test get existing project
	retrievedProject, err := store.GetProject(ctx, "org/repo2")
	assert.NoError(t, err)
	assert.Equal(t, project, retrievedProject)

	// Test get non-existent project
	_, err = store.GetProject(ctx, "non-existent/repo")
	assert.ErrorIs(t, err, server.ErrProjectNotFound)
}

func TestProjectDataStore_UpdateProject(t *testing.T) {
	store, ctx := setupProjectDataStore(t)

	project := cloudmodel.Project{
		OrgRepo: "org/repo3",
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test successful update
	err = store.UpdateProject(ctx, "org/repo3", func(p cloudmodel.Project) (cloudmodel.Project, error) {
		return p, nil
	})
	assert.NoError(t, err)

	_, err = store.GetProject(ctx, "org/repo3")
	require.NoError(t, err)

	// Test update non-existent project
	err = store.UpdateProject(ctx, "non-existent/repo", func(p cloudmodel.Project) (cloudmodel.Project, error) {
		return p, nil
	})
	assert.ErrorIs(t, err, server.ErrProjectNotFound)

	// Test update function error
	err = store.UpdateProject(ctx, "org/repo3", func(p cloudmodel.Project) (cloudmodel.Project, error) {
		return p, errors.New("update failed")
	})
	assert.ErrorContains(t, err, "update failed")

	// Test changing OrgRepo (should fail)
	err = store.UpdateProject(ctx, "org/repo3", func(p cloudmodel.Project) (cloudmodel.Project, error) {
		p.OrgRepo = "changed/repo"
		return p, nil
	})
	assert.ErrorContains(t, err, "cannot change OrgRepo")
}

func TestProjectDataStore_DeleteProject(t *testing.T) {
	store, ctx := setupProjectDataStore(t)

	project := cloudmodel.Project{OrgRepo: "org/repo4"}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test delete existing project
	err = store.DeleteProject(ctx, "org/repo4")
	assert.NoError(t, err)

	_, err = store.GetProject(ctx, "org/repo4")
	assert.ErrorIs(t, err, server.ErrProjectNotFound)

	// Test delete non-existent project
	err = store.DeleteProject(ctx, "non-existent/repo")
	assert.ErrorIs(t, err, server.ErrProjectNotFound) // Or assert.NoError if idempotent deletion is preferred
}

func TestProjectDataStore_ListProjects(t *testing.T) {
	store, ctx := setupProjectDataStore(t)

	project1 := cloudmodel.Project{OrgRepo: "list/repo1"}
	project2 := cloudmodel.Project{OrgRepo: "list/repo2"}
	err := store.CreateProject(ctx, project1)
	require.NoError(t, err)
	err = store.CreateProject(ctx, project2)
	require.NoError(t, err)

	projects, err := store.ListProjects(ctx)
	assert.NoError(t, err)
	assert.Len(t, projects, 2)
	// Note: Order is not guaranteed
	assert.Contains(t, projects, project1)
	assert.Contains(t, projects, project2)

	// Test list when empty
	err = store.DeleteProject(ctx, project1.OrgRepo)
	require.NoError(t, err)
	err = store.DeleteProject(ctx, project2.OrgRepo)
	require.NoError(t, err)

	projects, err = store.ListProjects(ctx)
	assert.NoError(t, err)
	assert.Len(t, projects, 0)
	assert.NotNil(t, projects) // Should return empty slice, not nil
}
