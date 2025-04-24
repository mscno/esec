package stores

import (
	"encoding/json"
	"errors"
	"fmt"
	"go.etcd.io/bbolt"
)

type BoltUserStore struct {
	db *bbolt.DB
}

var userBucket = []byte("users")

func NewBoltUserStore(db *bbolt.DB) (*BoltUserStore, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
	}
	// Ensure bucket exists
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(userBucket)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &BoltUserStore{db: db}, nil
}

func (s *BoltUserStore) RegisterUser(user User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(userBucket)
		key := []byte(user.GitHubID)
		if b.Get(key) != nil {
			return fmt.Errorf("user already exists")
		}
		val, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put(key, val)
	})
}

func (s *BoltUserStore) UpdateUserPublicKey(githubID, publicKey string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(userBucket)
		key := []byte(githubID)
		val := b.Get(key)
		if val == nil {
			return fmt.Errorf("user not found")
		}
		var user User
		if err := json.Unmarshal(val, &user); err != nil {
			return err
		}
		user.PublicKey = publicKey
		newVal, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put(key, newVal)
	})
}

func (s *BoltUserStore) GetUser(githubID string) (*User, error) {
	var user User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(userBucket)
		val := b.Get([]byte(githubID))
		if val == nil {
			return fmt.Errorf("user not found")
		}
		return json.Unmarshal(val, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

var _ UserStore = (*BoltUserStore)(nil)
