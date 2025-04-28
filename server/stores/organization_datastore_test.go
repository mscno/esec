package stores

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	// Switch to testify for consistency with other tests
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// "github.com/alecthomas/assert/v2"
	"github.com/joho/godotenv"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
	// Remove testcontainers imports
	// "github.com/testcontainers/testcontainers-go"
	// "github.com/testcontainers/testcontainers-go/modules/gcloud"
)

// setupOrganizationDataStore sets up the datastore connection using env vars.
func setupOrganizationDataStore(t *testing.T) (server.OrganizationStore, context.Context) {
	t.Helper()
	ctx := context.Background()
	godotenv.Load("../../.env.test")
	// Use a unique project ID for testing to avoid conflicts
	// The actual project ID doesn't matter when using the emulator
	projectID := os.Getenv("TEST_DATASTORE_PROJECT")
	client, err := datastore.NewClientWithDatabase(ctx, projectID, "esec-test")

	require.NoError(t, err, "failed to create datastore client")

	store := NewOrganizationDataStore(slog.New(slog.NewTextHandler(os.Stderr, nil)),client, )

	// Clear all organization data before the test run
	q := datastore.NewQuery(organizationKind).KeysOnly()
	keys, err := client.GetAll(ctx, q, nil)
	if err == nil && len(keys) > 0 {
		err = client.DeleteMulti(ctx, keys)
		require.NoError(t, err, "failed to clear existing organization data")
	}

	t.Cleanup(func() {
		_ = client.Close() // Ensure client is closed after test
	})

	return store, ctx
}

func TestOrganizationDataStore_CRUD(t *testing.T) {
	store, ctx := setupOrganizationDataStore(t)

	org1 := &model.Organization{ID: "org1-ds", Name: "Test Org 1 DS", Type: model.OrganizationTypeTeam, OwnerGithubID: "owner1"}
	org2 := &model.Organization{ID: "org2-ds", Name: "Test Org 2 DS", Type: model.OrganizationTypePersonal, OwnerGithubID: "owner2"}

	// Create
	err := store.CreateOrganization(ctx, org1)
	assert.NoError(t, err)
	err = store.CreateOrganization(ctx, org2)
	assert.NoError(t, err)

	// Create Duplicate ID
	err = store.CreateOrganization(ctx, &model.Organization{ID: "org1-ds", Name: "Duplicate ID Org DS", Type: model.OrganizationTypeTeam, OwnerGithubID: "owner1"})
	assert.Error(t, err) // Should fail on duplicate ID

	// Create Duplicate Name
	err = store.CreateOrganization(ctx, &model.Organization{ID: "org3-ds", Name: "Test Org 1 DS", Type: model.OrganizationTypeTeam, OwnerGithubID: "owner3"})
	assert.Error(t, err) // Should fail on duplicate name

	// Get By ID
	retOrg1, err := store.GetOrganizationByID(ctx, "org1-ds")
	assert.NoError(t, err)
	assert.Equal(t, org1.ID, retOrg1.ID)
	assert.Equal(t, org1.Name, retOrg1.Name)
	assert.Equal(t, org1.Type, retOrg1.Type)
	assert.Equal(t, org1.OwnerGithubID, retOrg1.OwnerGithubID)
	assert.False(t, retOrg1.CreatedAt.IsZero()) // Check CreatedAt is set
	assert.False(t, retOrg1.UpdatedAt.IsZero()) // Check UpdatedAt is set

	// Get By ID Not Found
	_, err = store.GetOrganizationByID(ctx, "nonexistent-ds")
	assert.ErrorIs(t, err, server.ErrOrganizationNotFound) // Use testify's ErrorIs

	// Get By Name
	retOrg2, err := store.GetOrganizationByName(ctx, "Test Org 2 DS")
	assert.NoError(t, err)
	assert.Equal(t, org2.ID, retOrg2.ID)

	// Get By Name Not Found
	_, err = store.GetOrganizationByName(ctx, "Nonexistent Org DS")
	assert.ErrorIs(t, err, server.ErrOrganizationNotFound)

	// Update
	retOrg1Fetched, err := store.GetOrganizationByID(ctx, "org1-ds") // Fetch fresh copy
	require.NoError(t, err) // Use require if subsequent steps depend on this
	retOrg1Fetched.Name = "Updated Test Org 1 DS"
	updateTime := retOrg1Fetched.UpdatedAt
	time.Sleep(10 * time.Millisecond) // Ensure time difference for UpdatedAt check
	err = store.UpdateOrganization(ctx, retOrg1Fetched)
	assert.NoError(t, err)

	updatedOrg1, err := store.GetOrganizationByID(ctx, "org1-ds")
	assert.NoError(t, err)
	assert.Equal(t, "Updated Test Org 1 DS", updatedOrg1.Name)
	assert.Equal(t, org1.Type, updatedOrg1.Type)                           // Verify Type wasn't changed
	assert.Equal(t, org1.OwnerGithubID, updatedOrg1.OwnerGithubID)         // Verify Owner wasn't changed
	assert.Equal(t, retOrg1Fetched.CreatedAt.Unix(), updatedOrg1.CreatedAt.Unix()) // Verify CreatedAt preserved
	assert.True(t, updatedOrg1.UpdatedAt.After(updateTime))                  // Check UpdatedAt changed

	// Update Name Conflict
	updatedOrg1.Name = "Test Org 2 DS" // Name already taken by org2
	err = store.UpdateOrganization(ctx, updatedOrg1)
	assert.Error(t, err)

	// Update Not Found
	err = store.UpdateOrganization(ctx, &model.Organization{ID: "nonexistent-ds", Name: "No Such Org DS"})
	assert.ErrorIs(t, err, server.ErrOrganizationNotFound)

	// List
	list, err := store.ListOrganizations(ctx)
	assert.NoError(t, err)
	assert.Len(t, list, 2) // Length check using testify
	// Check contents without assuming order
	foundOrg1 := false
	foundOrg2 := false
	for _, org := range list {
		if org.ID == "org1-ds" {
			assert.Equal(t, "Updated Test Org 1 DS", org.Name)
			foundOrg1 = true
		}
		if org.ID == "org2-ds" {
			assert.Equal(t, "Test Org 2 DS", org.Name)
			foundOrg2 = true
		}
	}
	assert.True(t, foundOrg1, "Org1 not found in list")
	assert.True(t, foundOrg2, "Org2 not found in list")

	// Delete
	err = store.DeleteOrganization(ctx, "org1-ds")
	assert.NoError(t, err)

	// Delete Not Found (should not error)
	err = store.DeleteOrganization(ctx, "org1-ds")
	assert.NoError(t, err)
	err = store.DeleteOrganization(ctx, "nonexistent-ds")
	assert.NoError(t, err)

	// Verify Deletion
	_, err = store.GetOrganizationByID(ctx, "org1-ds")
	assert.ErrorIs(t, err, server.ErrOrganizationNotFound)

	listAfterDelete, err := store.ListOrganizations(ctx)
	assert.NoError(t, err)
	assert.Len(t, listAfterDelete, 1)
	assert.Equal(t, "org2-ds", listAfterDelete[0].ID)
}
