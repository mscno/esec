package store

import (
	"encoding/json"
	"fmt"
	"go.etcd.io/bbolt"
)

// BoltStore implements Store interface using BoltDB
// Bucket: "projects" -> key: org/repo, value: JSON-encoded map[string]string

type BoltStore struct {
	db *bbolt.DB
}

const bucketName = "projects"

func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	// Ensure bucket exists
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (b *BoltStore) CreateProject(orgRepo string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket.Get([]byte(orgRepo)) == nil {
			empty, _ := json.Marshal(map[string]string{})
			return bucket.Put([]byte(orgRepo), empty)
		}
		return nil
	})
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

func (b *BoltStore) Close() error {
	return b.db.Close()
}
