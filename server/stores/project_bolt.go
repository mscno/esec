package stores

import (
	"context"
	"encoding/json"

	"go.etcd.io/bbolt"
)

type BoltProjectStore struct {
	db *bbolt.DB
}

func NewBoltProjectStore(db *bbolt.DB) *BoltProjectStore {
	return &BoltProjectStore{db: db}
}

func (s *BoltProjectStore) CreateProject(ctx context.Context, project Project) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("projects"))
		if err != nil {
			return err
		}
		if bucket.Get([]byte(project.OrgRepo)) != nil {
			return ErrProjectExists
		}
		data, err := json.Marshal(project)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(project.OrgRepo), data)
	})
}

func (s *BoltProjectStore) GetProject(ctx context.Context, orgRepo string) (Project, error) {
	var project Project
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("projects"))
		if bucket == nil {
			return ErrProjectNotFound
		}
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(val, &project)
	})
	return project, err
}

func (s *BoltProjectStore) UpdateProject(ctx context.Context, orgRepo string, updateFn func(project Project) (Project, error)) error {

	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("projects"))
		if bucket == nil {
			return ErrProjectNotFound
		}
		projectBytes := bucket.Get([]byte(orgRepo))
		if projectBytes == nil {
			return ErrProjectNotFound
		}

		var project Project
		if err := json.Unmarshal(projectBytes, &project); err != nil {
			return err
		}
		project, err := updateFn(project)
		if err != nil {
			return err
		}
		data, err := json.Marshal(project)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(project.OrgRepo), data)
	})
}

func (s *BoltProjectStore) ListProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("projects"))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var p Project
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			projects = append(projects, p)
			return nil
		})
	})
	return projects, err
}

func (s *BoltProjectStore) DeleteProject(ctx context.Context, orgRepo string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("projects"))
		if bucket == nil {
			return ErrProjectNotFound
		}
		if bucket.Get([]byte(orgRepo)) == nil {
			return ErrProjectNotFound
		}
		return bucket.Delete([]byte(orgRepo))
	})
}

var _ NewProjectStore = (*BoltProjectStore)(nil)
