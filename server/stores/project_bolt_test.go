package stores

import (
	"go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
)

func TestBoltStore_BasicCRUD(t *testing.T) {
	dbPath := filepath.Join(os.TempDir(), "boltstore_test.db")
	defer os.Remove(dbPath)

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("failed to open BoltDB: %v", err)
	}
	defer db.Close()

	store, err := NewBoltStore(db)
	if err != nil {
		t.Fatalf("failed to create BoltStore: %v", err)
	}

	orgRepo := "myorg/myrepo"
	if err := store.CreateProject(orgRepo, "admin"); err != nil {
		t.Fatalf("failed to create project: %v", err)
	}
	if !store.ProjectExists(orgRepo) {
		t.Error("expected project to exist after creation")
	}

	secrets := map[string]string{"FOO": "bar", "BAZ": "qux"}
	perUserSecret := map[string]map[string]string{"admin": secrets}
	if err := store.SetPerUserSecrets(orgRepo, perUserSecret); err != nil {
		t.Fatalf("failed to set secrets: %v", err)
	}
	got, err := store.GetPerUserSecrets(orgRepo)
	if err != nil {
		t.Fatalf("failed to get secrets: %v", err)
	}
	if got["admin"]["FOO"] != "bar" || got["admin"]["BAZ"] != "qux" {
		t.Errorf("unexpected secrets: got %+v", got)
	}
}

func TestBoltStore_ProjectLifecycle(t *testing.T) {
	dbfile := "test_bolt_project.db"
	_ = os.Remove(dbfile)
	db, err := bbolt.Open(dbfile, 0600, nil)
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	defer os.Remove(dbfile)
	defer db.Close()
	store, err := NewBoltStore(db)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	orgRepo := "org/repo"
	adminID := "123"
	if err := store.CreateProject(orgRepo, adminID); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if !store.ProjectExists(orgRepo) {
		t.Fatalf("ProjectExists false")
	}
	if !store.IsProjectAdmin(orgRepo, adminID) {
		t.Fatalf("IsProjectAdmin false")
	}
	admins, err := store.GetProjectAdmins(orgRepo)
	if err != nil || len(admins) != 1 || admins[0] != adminID {
		t.Fatalf("GetProjectAdmins: %v admins=%v", err, admins)
	}
	secrets := map[string]string{"k1": "v1"}
	perUserSecret := map[string]map[string]string{"admin": secrets}

	if err := store.SetPerUserSecrets(orgRepo, perUserSecret); err != nil {
		t.Fatalf("SetSecrets: %v", err)
	}
	got, err := store.GetPerUserSecrets(orgRepo)
	if err != nil || got["admin"]["k1"] != "v1" {
		t.Fatalf("GetSecrets: %v got=%v", err, got)
	}
	perUser := map[string]map[string]string{"u1": {"k": "v"}}
	if err := store.SetPerUserSecrets(orgRepo, perUser); err != nil {
		t.Fatalf("SetPerUserSecrets: %v", err)
	}
	gotPU, err := store.GetPerUserSecrets(orgRepo)
	if err != nil || gotPU["u1"]["k"] != "v" {
		t.Fatalf("GetPerUserSecrets: %v got=%v", err, gotPU)
	}
}
