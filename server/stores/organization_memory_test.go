package stores

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
)

func TestOrganizationMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewOrganizationMemoryStore()

	org1 := &model.Organization{ID: "org1", Name: "Test Org 1"}
	org2 := &model.Organization{ID: "org2", Name: "Test Org 2"}

	// Create
	err := store.CreateOrganization(ctx, org1)
	assert.NoError(t, err)
	err = store.CreateOrganization(ctx, org2)
	assert.NoError(t, err)

	// Create Duplicate ID
	err = store.CreateOrganization(ctx, &model.Organization{ID: "org1", Name: "Duplicate ID Org"})
	assert.Error(t, err)

	// Create Duplicate Name
	err = store.CreateOrganization(ctx, &model.Organization{ID: "org3", Name: "Test Org 1"})
	assert.Error(t, err)

	// Get By ID
	retOrg1, err := store.GetOrganizationByID(ctx, "org1")
	assert.NoError(t, err)
	assert.Equal(t, org1.ID, retOrg1.ID)
	assert.Equal(t, org1.Name, retOrg1.Name)
	assert.NotZero(t, retOrg1.CreatedAt)
	assert.NotZero(t, retOrg1.UpdatedAt)

	// Get By ID Not Found
	_, err = store.GetOrganizationByID(ctx, "nonexistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, server.ErrOrganizationNotFound))

	// Get By Name
	retOrg2, err := store.GetOrganizationByName(ctx, "Test Org 2")
	assert.NoError(t, err)
	assert.Equal(t, org2.ID, retOrg2.ID)

	// Get By Name Not Found
	_, err = store.GetOrganizationByName(ctx, "Nonexistent Org")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, server.ErrOrganizationNotFound))

	// Update
	retOrg1.Name = "Updated Test Org 1"
	updateTime := retOrg1.UpdatedAt
	// Ensure Update doesn't zero out CreatedAt if not provided
	retOrg1.CreatedAt = time.Time{}
	err = store.UpdateOrganization(ctx, retOrg1)
	assert.NoError(t, err)

	updatedOrg1, err := store.GetOrganizationByID(ctx, "org1")
	assert.NoError(t, err)
	assert.Equal(t, "Updated Test Org 1", updatedOrg1.Name)
	assert.NotZero(t, updatedOrg1.CreatedAt) // Check CreatedAt was preserved
	assert.True(t, updatedOrg1.UpdatedAt.After(updateTime)) // Check UpdatedAt changed

	// Update Name Conflict
	updatedOrg1.Name = "Test Org 2" // Name already taken by org2
	err = store.UpdateOrganization(ctx, updatedOrg1)
	assert.Error(t, err)

	// Update Not Found
	err = store.UpdateOrganization(ctx, &model.Organization{ID: "nonexistent", Name: "No Such Org"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, server.ErrOrganizationNotFound))

	// List
	list, err := store.ListOrganizations(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(list))
	assert.Equal(t, "Test Org 2", list[0].Name)          // Check sorting
	assert.Equal(t, "Updated Test Org 1", list[1].Name) // Check sorting

	// Delete
	err = store.DeleteOrganization(ctx, "org1")
	assert.NoError(t, err)

	// Delete Not Found (should not error)
	err = store.DeleteOrganization(ctx, "org1")
	assert.NoError(t, err)
	err = store.DeleteOrganization(ctx, "nonexistent")
	assert.NoError(t, err)

	// Verify Deletion
	_, err = store.GetOrganizationByID(ctx, "org1")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, server.ErrOrganizationNotFound))
	_, err = store.GetOrganizationByName(ctx, "Updated Test Org 1") // Name should also be gone
	assert.Error(t, err)
	assert.True(t, errors.Is(err, server.ErrOrganizationNotFound))

	listAfterDelete, err := store.ListOrganizations(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(listAfterDelete))
	assert.Equal(t, "org2", listAfterDelete[0].ID)
}
