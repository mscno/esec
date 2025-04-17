package store

import (
	"encoding/json"
	"fmt"
	"go.etcd.io/bbolt"
)

// BoltStore implements Store interface using BoltDB
// Bucket: "projects" -> key: org/repo, value: JSON-encoded map[string]string
// Bucket: "projects_per_user" -> key: org/repo, value: JSON-encoded map[string]map[string]string
// Bucket: "project_meta" -> key: org/repo, value: JSON-encoded ProjectMeta

type ProjectMeta struct {
	Admins []string `json:"admins"`
}

type BoltStore struct {
	db *bbolt.DB
}

const bucketName = "projects"
const perUserBucket = "projects_per_user"
const metaBucket = "project_meta"

func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	// Ensure buckets exist
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketName)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(perUserBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(metaBucket)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (b *BoltStore) CreateProject(orgRepo string, adminID string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		metaB := tx.Bucket([]byte(metaBucket))
		if bucket.Get([]byte(orgRepo)) == nil {
			empty, _ := json.Marshal(map[string]string{})
			if err := bucket.Put([]byte(orgRepo), empty); err != nil {
				return err
			}
			meta := ProjectMeta{Admins: []string{adminID}}
			metaBytes, _ := json.Marshal(meta)
			return metaB.Put([]byte(orgRepo), metaBytes)
		}
		return nil
	})
}

func (b *BoltStore) GetProjectAdmins(orgRepo string) ([]string, error) {
	var meta ProjectMeta
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(metaBucket))
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return fmt.Errorf("project not found")
		}
		return json.Unmarshal(val, &meta)
	})
	if err != nil {
		return nil, err
	}
	return append([]string{}, meta.Admins...), nil
}

func (b *BoltStore) IsProjectAdmin(orgRepo string, githubID string) bool {
	admins, err := b.GetProjectAdmins(orgRepo)
	if err != nil {
		return false
	}
	for _, admin := range admins {
		if admin == githubID {
			return true
		}
	}
	return false
}

func (b *BoltStore) ProjectExists(orgRepo string) bool {
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket.Get([]byte(orgRepo)) == nil {
			return fmt.Errorf("not found")
		}
		return nil
	})
	return err == nil
}

func (b *BoltStore) GetSecrets(orgRepo string) (map[string]string, error) {
	var result map[string]string
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return fmt.Errorf("project not found")
		}
		return json.Unmarshal(val, &result)
	})
	return result, err
}

func (b *BoltStore) SetSecrets(orgRepo string, secrets map[string]string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		val, err := json.Marshal(secrets)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(orgRepo), val)
	})
}

func (b *BoltStore) GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error) {
	var result map[string]map[string]string
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(perUserBucket))
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			result = make(map[string]map[string]string)
			return nil
		}
		return json.Unmarshal(val, &result)
	})
	return result, err
}

func (b *BoltStore) SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(perUserBucket))
		val, err := json.Marshal(secrets)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(orgRepo), val)
	})
}

func (b *BoltStore) Close() error {
	return b.db.Close()
}
