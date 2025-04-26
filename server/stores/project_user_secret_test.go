package stores

import (
	"cloud.google.com/go/datastore"
	"context"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestUserSecretsDataStore(t *testing.T) {
	testUserSecrets(t, func() ProjectStore {
		ctx := context.Background()
		projectID := os.Getenv("TEST_DATASTORE_PROJECT")
		client, err := datastore.NewClientWithDatabase(ctx, projectID, "esec-test")
		assert.NoError(t, err)
		store := NewProjectDataStore(ctx, client)

		return store
	})
}
func TestUserSecretsInMemory(t *testing.T) {
	testUserSecrets(t, func() ProjectStore {
		return NewInMemoryProjectStore()
	})
}

func TestUserSecretsBolt(t *testing.T) {
	dbfile := "test_user_secrets_bolt.db"
	_ = os.Remove(dbfile) // Clean up from previous tests

	db, err := bbolt.Open(dbfile, 0600, nil)
	require.NoError(t, err)

	defer func() {
		db.Close()
		os.Remove(dbfile)
	}()

	testUserSecrets(t, func() ProjectStore {
		return NewBoltProjectStore(db)
	})
}

func testUserSecrets(t *testing.T, storeFactory func() ProjectStore) {
	ctx := context.Background()
	store := storeFactory()

	// Create test project
	project := Project{
		OrgRepo: "test-org/test-repo" + rand.Text(),
		Admins:  []string{"admin1"},
	}

	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	defer func() {
		_ = store.DeleteProject(ctx, project.OrgRepo)
	}()

	// Test setting and getting secrets for a user
	t.Run("Set and get user secrets", func(t *testing.T) {
		// Set secrets for user1
		user1Secrets := map[string]string{
			"API_KEY": "secret1",
			"TOKEN":   "token1",
		}

		err := store.SetProjectUserSecrets(ctx, project.OrgRepo, "user1", user1Secrets)
		assert.NoError(t, err)

		// Get secrets for user1
		gotSecrets, err := store.GetProjectUserSecrets(ctx, project.OrgRepo, "user1")
		assert.NoError(t, err)
		assert.Equal(t, user1Secrets, gotSecrets)

		// Set secrets for user2
		user2Secrets := map[string]string{
			"DB_PASSWORD": "dbpass",
		}

		err = store.SetProjectUserSecrets(ctx, project.OrgRepo, "user2", user2Secrets)
		assert.NoError(t, err)

		// Get all project secrets
		allSecrets, err := store.GetAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)
		assert.Len(t, allSecrets, 2)
		assert.Equal(t, user1Secrets, allSecrets["user1"])
		assert.Equal(t, user2Secrets, allSecrets["user2"])
	})

	t.Run("Update user secrets", func(t *testing.T) {
		// Update user1's secrets
		updatedSecrets := map[string]string{
			"API_KEY": "newsecret",
			"CERT":    "newcert",
		}

		err := store.SetProjectUserSecrets(ctx, project.OrgRepo, "user1", updatedSecrets)
		assert.NoError(t, err)

		// Verify the update
		gotSecrets, err := store.GetProjectUserSecrets(ctx, project.OrgRepo, "user1")
		assert.NoError(t, err)
		assert.Equal(t, updatedSecrets, gotSecrets)
		assert.NotContains(t, gotSecrets, "TOKEN") // Old key should be gone
	})

	t.Run("Delete user secrets", func(t *testing.T) {
		// Delete user1's secrets
		err := store.DeleteProjectUserSecrets(ctx, project.OrgRepo, "user1")
		assert.NoError(t, err)

		// Verify user1's secrets are gone
		secrets, err := store.GetProjectUserSecrets(ctx, project.OrgRepo, "user1")
		assert.NoError(t, err)
		assert.Empty(t, secrets)

		// Verify user2's secrets still exist
		allSecrets, err := store.GetAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)
		assert.Len(t, allSecrets, 1)
		assert.Contains(t, allSecrets, "user2")
	})

	t.Run("Delete all user secrets", func(t *testing.T) {
		// Delete all project secrets
		_, err := store.GetAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)

		err = store.DeleteAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)

		// Verify all secrets are gone
		allSecrets, err := store.GetAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)
		assert.Empty(t, allSecrets)
	})

	t.Run("Project not found errors", func(t *testing.T) {
		// Test with non-existent project
		_, err := store.GetAllProjectUserSecrets(ctx, "non-existent/repo")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProjectNotFound)

		_, err = store.GetProjectUserSecrets(ctx, "non-existent/repo", "user1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProjectNotFound)

		err = store.SetProjectUserSecrets(ctx, "non-existent/repo", "user1", map[string]string{"key": "value"})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProjectNotFound)
	})

	t.Run("Project deletion cascades to secrets", func(t *testing.T) {
		// Add a secret for testing
		err := store.SetProjectUserSecrets(ctx, project.OrgRepo, "user3", map[string]string{"key": "value"})
		assert.NoError(t, err)

		// Delete the project
		err = store.DeleteProject(ctx, project.OrgRepo)
		assert.NoError(t, err)

		// Create the project again (to verify secrets were deleted)
		err = store.CreateProject(ctx, project)
		assert.NoError(t, err)

		// Verify no secrets exist
		allSecrets, err := store.GetAllProjectUserSecrets(ctx, project.OrgRepo)
		assert.NoError(t, err)
		assert.Empty(t, allSecrets)
	})
}

func TestSecretPairsConversion(t *testing.T) {
	t.Run("map to pairs and back", func(t *testing.T) {
		// Start with a map
		originalMap := map[string]string{
			"API_KEY":    "secret-key-1",
			"DB_PASS":    "password123",
			"AUTH_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		}

		// Convert to pairs
		pairs := mapToSecretPairs(originalMap)

		// Verify all keys and values are in the pairs
		assert.Len(t, pairs, len(originalMap))
		keyFound := make(map[string]bool)
		for _, pair := range pairs {
			assert.Equal(t, originalMap[pair.Key], pair.Value)
			keyFound[pair.Key] = true
		}

		// Verify all keys were found in pairs
		for k := range originalMap {
			assert.True(t, keyFound[k], "Key %s not found in pairs", k)
		}

		// Convert back to map
		resultMap := secretPairsToMap(pairs)

		// Verify the result map matches the original
		assert.Equal(t, originalMap, resultMap)
	})

	t.Run("empty map", func(t *testing.T) {
		// Test with empty map
		emptyMap := map[string]string{}
		pairs := mapToSecretPairs(emptyMap)
		assert.Empty(t, pairs)

		// Convert back
		resultMap := secretPairsToMap(pairs)
		assert.Equal(t, emptyMap, resultMap)
	})

	t.Run("nil map", func(t *testing.T) {
		// Test with nil map
		var nilMap map[string]string
		pairs := mapToSecretPairs(nilMap)
		assert.Empty(t, pairs)

		// Convert back
		resultMap := secretPairsToMap(pairs)
		assert.NotNil(t, resultMap)
		assert.Empty(t, resultMap)
	})

	t.Run("duplicate keys", func(t *testing.T) {
		// Create pairs with duplicate keys (invalid state but should be handled)
		pairs := []SecretPair{
			{Key: "API_KEY", Value: "value1"},
			{Key: "DB_PASS", Value: "value2"},
			{Key: "API_KEY", Value: "value3"}, // Duplicate
		}

		// Convert to map - last value should win
		resultMap := secretPairsToMap(pairs)
		assert.Len(t, resultMap, 2)
		assert.Equal(t, "value3", resultMap["API_KEY"])
		assert.Equal(t, "value2", resultMap["DB_PASS"])
	})
}
