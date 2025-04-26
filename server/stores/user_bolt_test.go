package stores

import (
	"context"
	"github.com/mscno/esec/pkg/cloudmodel"
	"os"
	"testing"

	"go.etcd.io/bbolt"
)

func TestBoltUserStore_CRUD(t *testing.T) {
	dbfile := "test_bolt_user_crud.db"
	_ = os.Remove(dbfile)
	db, err := bbolt.Open(dbfile, 0600, nil)
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	defer os.Remove(dbfile)
	defer db.Close()
	store := NewBoltUserStore(db)

	user := cloudmodel.User{
		GitHubID:  "1",
		Username:  "alice",
		PublicKey: "pk1",
	}
	ctx := context.Background()
	// Create
	err = store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Get
	u, err := store.GetUser(ctx, "1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("unexpected user: %+v", u)
	}

	// Update
	err = store.UpdateUser(ctx, "1", func(u cloudmodel.User) (cloudmodel.User, error) {
		u.PublicKey = "pk2"
		return u, nil
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	u, _ = store.GetUser(ctx, "1")
	if u.PublicKey != "pk2" {
		t.Errorf("update failed: %+v", u)
	}

	// List
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].GitHubID != "1" {
		t.Errorf("unexpected users: %+v", users)
	}

	// Delete
	err = store.DeleteUser(ctx, "1")
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err = store.GetUser(ctx, "1")
	if err == nil {
		t.Errorf("expected error after delete, got nil")
	}
}
