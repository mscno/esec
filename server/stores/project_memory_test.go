package stores

import (
	"context"
	"github.com/mscno/esec/pkg/cloudmodel"
	"testing"
)

func TestInMemoryProjectStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryProjectStore()

	project := cloudmodel.Project{
		OrgRepo: "org/repo",
	}

	// Create
	err := store.CreateProject(ctx, project)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// Get
	got, err := store.GetProject(ctx, "org/repo")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.OrgRepo != project.OrgRepo {
		t.Errorf("unexpected project: %+v", got)
	}

	// Update
	err = store.UpdateProject(ctx, "org/repo", func(p cloudmodel.Project) (cloudmodel.Project, error) {
		return p, nil
	})
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	got, err = store.GetProject(ctx, "org/repo")
	if err != nil {
		t.Fatalf("GetProject after update: %v", err)
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
