package stores

import "testing"

func TestMemoryUserStore_UserLifecycle(t *testing.T) {
	s := NewMemoryUserStore()
	u := User{GitHubID: "42", Username: "alice", PublicKey: "pk"}
	if err := s.RegisterUser(u); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if err := s.RegisterUser(u); err != ErrUserExists {
		t.Fatalf("expected ErrUserExists, got: %v", err)
	}
	user, err := s.GetUser("42")
	if err != nil || user.Username != "alice" {
		t.Fatalf("GetUser: %v user=%v", err, user)
	}
	if err := s.UpdateUserPublicKey("42", "pk2"); err != nil {
		t.Fatalf("UpdateUserPublicKey: %v", err)
	}
	user, err = s.GetUser("42")
	if err != nil || user.PublicKey != "pk2" {
		t.Fatalf("GetUser after update: %v user=%v", err, user)
	}
	if _, err := s.GetUser("notfound"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}
}
