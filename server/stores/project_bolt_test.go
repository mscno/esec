package stores

import (
	"context"
	"os"
	"testing"

	"go.etcd.io/bbolt"
)

func TestBoltProjectStore_CRUD(t *testing.T) {
	ctx := context.Background()
	dbfile := "test_bolt_project_crud.db"
	_ = os.Remove(dbfile)
	db, err := bbolt.Open(dbfile, 0600, nil)
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	defer os.Remove(dbfile)
	defer db.Close()
	store := NewBoltProjectStore(db)

	project := Project{
		OrgRepo: "org/repo",
		Admins:  []string{"admin"},
	}

	// Create
	err = store.CreateProject(ctx, project)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// Get
	got, err := store.GetProject(ctx, "org/repo")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.OrgRepo != project.OrgRepo || len(got.Admins) != 1 || got.Admins[0] != "admin" {
		t.Errorf("unexpected project: %+v", got)
	}

	// Update
	err = store.UpdateProject(ctx, "org/repo", func(p Project) (Project, error) {
		p.Admins = append(p.Admins, "admin2")
		return p, nil
	})
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	got, err = store.GetProject(ctx, "org/repo")
	if err != nil {
		t.Fatalf("GetProject after update: %v", err)
	}
	if len(got.Admins) != 2 || got.Admins[1] != "admin2" {
		t.Errorf("update failed: %+v", got)
	}

	// List
	projects, err := store.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].OrgRepo != "org/repo" {
		t.Errorf("unexpected projects: %+v", projects)
	}

	// Delete
	err = store.DeleteProject(ctx, "org/repo")
	if err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	_, err = store.GetProject(ctx, "org/repo")
	if err == nil {
		t.Errorf("expected error after delete, got nil")
	}
}
