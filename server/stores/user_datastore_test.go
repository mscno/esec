package stores

import (
	"cloud.google.com/go/datastore"
	"context"
	"errors"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
	"google.golang.org/api/option"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupUserDataStore sets up the Datastore emulator connection for tests.
func setupUserDataStore(t *testing.T) (*UserDataStore, context.Context) {
	t.Helper()
	ctx := context.Background()

	host := os.Getenv("DATASTORE_EMULATOR_HOST")
	if host == "" {
		t.Skip("Skipping Datastore tests: DATASTORE_EMULATOR_HOST not set. Run 'gcloud beta emulators datastore start' first.")
	}

	// Use a unique project ID for testing to avoid conflicts
	// The actual project ID doesn't matter when using the emulator
	projectID := "test-project-users"
	client, err := datastore.NewClient(ctx, projectID, option.WithEndpoint(host))
	assert.NoError(t, err)
	store := NewUserDataStore(ctx, client)

	// Clear all data before each test run (optional, but good practice)
	q := datastore.NewQuery(userKind).KeysOnly()
	keys, err := store.client.GetAll(ctx, q, nil)
	if err == nil && len(keys) > 0 {
		_ = store.client.DeleteMulti(ctx, keys) // Ignore error during cleanup
	}

	t.Cleanup(func() {
		_ = store.Close() // Ensure client is closed after test
	})

	return store, ctx
}

func TestUserDataStore_CreateUser(t *testing.T) {
	store, ctx := setupUserDataStore(t)

	user := model.User{GitHubID: "test-user-1", Username: "Test User 1", PublicKey: "key1"}

	// Test successful creation
	err := store.CreateUser(ctx, user)
	assert.NoError(t, err)

	// Test creating existing user
	err = store.CreateUser(ctx, user)
	assert.ErrorIs(t, err, server.ErrUserExists)
}

func TestUserDataStore_GetUser(t *testing.T) {
	store, ctx := setupUserDataStore(t)

	user := model.User{GitHubID: "test-user-2", Username: "Test User 2", PublicKey: "key2"}
	err := store.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test get existing user
	retrievedUser, err := store.GetUser(ctx, "test-user-2")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, user, *retrievedUser)

	// Test get non-existent user
	_, err = store.GetUser(ctx, "non-existent-user")
	assert.ErrorIs(t, err, server.ErrUserNotFound)
}

func TestUserDataStore_UpdateUser(t *testing.T) {
	store, ctx := setupUserDataStore(t)

	user := model.User{GitHubID: "test-user-3", Username: "Test User 3", PublicKey: "key3"}
	err := store.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test successful update
	err = store.UpdateUser(ctx, "test-user-3", func(u model.User) (model.User, error) {
		u.PublicKey = "newkey3"
		return u, nil
	})
	assert.NoError(t, err)

	updatedUser, err := store.GetUser(ctx, "test-user-3")
	require.NoError(t, err)
	assert.Equal(t, "newkey3", updatedUser.PublicKey)

	// Test update non-existent user
	err = store.UpdateUser(ctx, "non-existent-user", func(u model.User) (model.User, error) {
		return u, nil
	})
	assert.ErrorIs(t, err, server.ErrUserNotFound)

	// Test update function error
	err = store.UpdateUser(ctx, "test-user-3", func(u model.User) (model.User, error) {
		return u, errors.New("update failed")
	})
	assert.ErrorContains(t, err, "update failed")

	// Test changing GitHubID (should fail)
	err = store.UpdateUser(ctx, "test-user-3", func(u model.User) (model.User, error) {
		u.GitHubID = "changed-id"
		return u, nil
	})
	assert.ErrorContains(t, err, "cannot change GitHubID")
}

func TestUserDataStore_DeleteUser(t *testing.T) {
	store, ctx := setupUserDataStore(t)

	user := model.User{GitHubID: "test-user-4", Username: "Test User 4", PublicKey: "key4"}
	err := store.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test delete existing user
	err = store.DeleteUser(ctx, "test-user-4")
	assert.NoError(t, err)

	_, err = store.GetUser(ctx, "test-user-4")
	assert.ErrorIs(t, err, server.ErrUserNotFound)

	// Test delete non-existent user
	err = store.DeleteUser(ctx, "non-existent-user")
	assert.ErrorIs(t, err, server.ErrUserNotFound) // Or assert.NoError if idempotent deletion is preferred
}

func TestUserDataStore_ListUsers(t *testing.T) {
	store, ctx := setupUserDataStore(t)

	user1 := model.User{GitHubID: "list-user-1", Username: "List User 1", PublicKey: "keyL1"}
	user2 := model.User{GitHubID: "list-user-2", Username: "List User 2", PublicKey: "keyL2"}
	err := store.CreateUser(ctx, user1)
	require.NoError(t, err)
	err = store.CreateUser(ctx, user2)
	require.NoError(t, err)

	users, err := store.ListUsers(ctx)
	assert.NoError(t, err)
	assert.Len(t, users, 2)
	// Note: Order is not guaranteed in Datastore list operations without explicit ordering
	assert.Contains(t, users, user1)
	assert.Contains(t, users, user2)

	// Test list when empty
	err = store.DeleteUser(ctx, user1.GitHubID)
	require.NoError(t, err)
	err = store.DeleteUser(ctx, user2.GitHubID)
	require.NoError(t, err)

	users, err = store.ListUsers(ctx)
	assert.NoError(t, err)
	assert.Len(t, users, 0)
	assert.NotNil(t, users) // Should return empty slice, not nil
}
