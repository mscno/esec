package stores

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.etcd.io/bbolt"
)

type BoltProjectStore struct {
	db *bbolt.DB
}

func NewBoltProjectStore(db *bbolt.DB) *BoltProjectStore {
	return &BoltProjectStore{db: db}
}

var (
	projectsBucket       = []byte("projects")
	projectSecretsBucket = []byte("project_secrets")
)

func (s *BoltProjectStore) CreateProject(ctx context.Context, project Project) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(projectsBucket)
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
		bucket := tx.Bucket(projectsBucket)
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
		bucket := tx.Bucket(projectsBucket)
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
		bucket := tx.Bucket(projectsBucket)
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
	// First delete all user secrets for this project
	if err := s.DeleteAllProjectUserSecrets(ctx, orgRepo); err != nil {
		return err
	}

	// Then delete the project itself
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		if bucket == nil {
			return ErrProjectNotFound
		}
		if bucket.Get([]byte(orgRepo)) == nil {
			return ErrProjectNotFound
		}
		return bucket.Delete([]byte(orgRepo))
	})
}

// Key format for project user secrets: "orgRepo:userID"
func makeSecretsKey(orgRepo, userID string) []byte {
	return []byte(fmt.Sprintf("%s:%s", orgRepo, userID))
}

// parseSecretsKey parses a key to extract orgRepo and userID
func parseSecretsKey(key []byte) (orgRepo, userID string) {
	parts := strings.SplitN(string(key), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func (s *BoltProjectStore) SetProjectUserSecrets(ctx context.Context, orgRepo string, userID string, secrets map[string]string) error {
	// First verify the project exists
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return err
	}

	// Then store the user secrets
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(projectSecretsBucket)
		if err != nil {
			return err
		}

		data, err := json.Marshal(secrets)
		if err != nil {
			return err
		}

		key := makeSecretsKey(orgRepo, userID)
		return bucket.Put(key, data)
	})
}

func (s *BoltProjectStore) GetProjectUserSecrets(ctx context.Context, orgRepo string, userID string) (map[string]string, error) {
	// First verify the project exists
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return nil, err
	}

	var secrets map[string]string
	err = s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectSecretsBucket)
		if bucket == nil {
			secrets = make(map[string]string)
			return nil
		}

		key := makeSecretsKey(orgRepo, userID)
		val := bucket.Get(key)
		if val == nil {
			secrets = make(map[string]string)
			return nil
		}

		return json.Unmarshal(val, &secrets)
	})

	return secrets, err
}

func (s *BoltProjectStore) GetAllProjectUserSecrets(ctx context.Context, orgRepo string) (map[string]map[string]string, error) {
	// First verify the project exists
	_, err := s.GetProject(ctx, orgRepo)
	if err != nil {
		return nil, err
	}

	result := make(map[string]map[string]string)

	err = s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectSecretsBucket)
		if bucket == nil {
			return nil
		}

		prefix := []byte(orgRepo + ":")
		c := bucket.Cursor()

		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			_, userID := parseSecretsKey(k)
			if userID == "" {
				continue
			}

			var secrets map[string]string
			if err := json.Unmarshal(v, &secrets); err != nil {
				return err
			}

			result[userID] = secrets
		}

		return nil
	})

	return result, err
}

func (s *BoltProjectStore) DeleteProjectUserSecrets(ctx context.Context, orgRepo string, userID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectSecretsBucket)
		if bucket == nil {
			return nil // Nothing to delete
		}

		key := makeSecretsKey(orgRepo, userID)
		return bucket.Delete(key)
	})
}

func (s *BoltProjectStore) DeleteAllProjectUserSecrets(ctx context.Context, orgRepo string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectSecretsBucket)
		if bucket == nil {
			return nil
		}

		prefix := []byte(orgRepo + ":")
		c := bucket.Cursor()

		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		return nil
	})
}

// Ensure BoltProjectStore implements ProjectStore
var _ ProjectStore = (*BoltProjectStore)(nil)
