package stores

import (
	"go.etcd.io/bbolt"
	"os"
	"testing"
)

func TestBoltUserStore_UserLifecycle(t *testing.T) {
	dbfile := "test_bolt_user.db"
	_ = os.Remove(dbfile)
	db, err := bbolt.Open(dbfile, 0600, nil)
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	defer os.Remove(dbfile)
	defer db.Close()
	store, err := NewBoltUserStore(db)
	if err != nil {
		t.Fatalf("NewBoltUserStore: %v", err)
	}
	u := User{GitHubID: "42", Username: "alice", PublicKey: "pk"}
	if err := store.RegisterUser(u); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if err := store.RegisterUser(u); err.Error() != ErrUserExists.Error() {
		t.Fatalf("expected ErrUserExists, got: %v", err)
	}
	user, err := store.GetUser("42")
	if err != nil || user.Username != "alice" {
		t.Fatalf("GetUser: %v user=%v", err, user)
	}
	if err := store.UpdateUserPublicKey("42", "pk2"); err != nil {
		t.Fatalf("UpdateUserPublicKey: %v", err)
	}
	user, err = store.GetUser("42")
	if err != nil || user.PublicKey != "pk2" {
		t.Fatalf("GetUser after update: %v user=%v", err, user)
	}
	if _, err := store.GetUser("notfound"); err.Error() != ErrUserNotFound.Error() {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}
}
