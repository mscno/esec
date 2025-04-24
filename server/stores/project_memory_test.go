package stores

import (
	"testing"
)

func TestMemoryStore_ProjectLifecycle(t *testing.T) {
	s := NewMemoryStore()
	orgRepo := "org/repo"
	adminID := "123"
	// Create
	if err := s.CreateProject(orgRepo, adminID); err != nil {
		t.Fatalf("CreateProject failed: %v", err)
	}
	// Exists
	if !s.ProjectExists(orgRepo) {
		t.Fatalf("ProjectExists returned false")
	}
	// Admin
	if !s.IsProjectAdmin(orgRepo, adminID) {
		t.Fatalf("IsProjectAdmin returned false")
	}
	admins, err := s.GetProjectAdmins(orgRepo)
	if err != nil || len(admins) != 1 || admins[0] != adminID {
		t.Fatalf("GetProjectAdmins failed: %v admins=%v", err, admins)
	}
	// Secrets
	secrets := map[string]string{"k1": "v1"}
	if err := s.SetSecrets(orgRepo, secrets); err != nil {
		t.Fatalf("SetSecrets failed: %v", err)
	}
	got, err := s.GetSecrets(orgRepo)
	if err != nil || got["k1"] != "v1" {
		t.Fatalf("GetSecrets failed: %v got=%v", err, got)
	}
	// Per-user secrets
	perUser := map[string]map[string]string{"u1": {"k": "v"}}
	if err := s.SetPerUserSecrets(orgRepo, perUser); err != nil {
		t.Fatalf("SetPerUserSecrets failed: %v", err)
	}
	gotPU, err := s.GetPerUserSecrets(orgRepo)
	if err != nil || gotPU["u1"]["k"] != "v" {
		t.Fatalf("GetPerUserSecrets failed: %v got=%v", err, gotPU)
	}
}
