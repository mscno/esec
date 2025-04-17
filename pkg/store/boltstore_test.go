package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoltStore_BasicCRUD(t *testing.T) {
	dbPath := filepath.Join(os.TempDir(), "boltstore_test.db")
	defer os.Remove(dbPath)

	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create BoltStore: %v", err)
	}
	defer store.Close()

	orgRepo := "myorg/myrepo"
	if err := store.CreateProject(orgRepo, "admin"); err != nil {
		t.Fatalf("failed to create project: %v", err)
	}
	if !store.ProjectExists(orgRepo) {
		t.Error("expected project to exist after creation")
	}

	secrets := map[string]string{"FOO": "bar", "BAZ": "qux"}
	if err := store.SetSecrets(orgRepo, secrets); err != nil {
		t.Fatalf("failed to set secrets: %v", err)
	}
	got, err := store.GetSecrets(orgRepo)
	if err != nil {
		t.Fatalf("failed to get secrets: %v", err)
	}
	if got["FOO"] != "bar" || got["BAZ"] != "qux" {
		t.Errorf("unexpected secrets: got %+v", got)
	}
}
