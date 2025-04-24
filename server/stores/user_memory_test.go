package stores

import (
	"testing"
)

func TestInMemoryUserStore_CRUD(t *testing.T) {
	store := NewInMemoryUserStore()
	user := User{
		GitHubID:  "1",
		Username:  "alice",
		PublicKey: "pk1",
	}

	// Create
	err := store.CreateUser(user)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Get
	u, err := store.GetUser("1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("unexpected user: %+v", u)
	}

	// Update
	err = store.UpdateUser("1", func(u User) (User, error) {
		u.PublicKey = "pk2"
		return u, nil
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	u, _ = store.GetUser("1")
	if u.PublicKey != "pk2" {
		t.Errorf("update failed: %+v", u)
	}

	// List
	users, err := store.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].GitHubID != "1" {
		t.Errorf("unexpected users: %+v", users)
	}

	// Delete
	err = store.DeleteUser("1")
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err = store.GetUser("1")
	if err == nil {
		t.Errorf("expected error after delete, got nil")
	}
}
