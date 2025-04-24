package stores

import (
	"encoding/json"
	"go.etcd.io/bbolt"
)

type BoltUserStore struct {
	db *bbolt.DB
}

func NewBoltUserStore(db *bbolt.DB) *BoltUserStore {
	return &BoltUserStore{db: db}
}

var usersBucket = []byte("users")

func (s *BoltUserStore) CreateUser(user User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(usersBucket)
		if err != nil {
			return err
		}
		if bucket.Get([]byte(user.GitHubID)) != nil {
			return ErrUserExists
		}
		data, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.GitHubID), data)
	})
}

func (s *BoltUserStore) GetUser(githubID string) (*User, error) {
	var user User
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return ErrUserNotFound
		}
		val := bucket.Get([]byte(githubID))
		if val == nil {
			return ErrUserNotFound
		}
		return json.Unmarshal(val, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *BoltUserStore) UpdateUser(githubID string, updateFn func(User) (User, error)) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return ErrUserNotFound
		}
		val := bucket.Get([]byte(githubID))
		if val == nil {
			return ErrUserNotFound
		}
		var user User
		if err := json.Unmarshal(val, &user); err != nil {
			return err
		}
		updated, err := updateFn(user)
		if err != nil {
			return err
		}
		data, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(githubID), data)
	})
}

func (s *BoltUserStore) DeleteUser(githubID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return ErrUserNotFound
		}
		if bucket.Get([]byte(githubID)) == nil {
			return ErrUserNotFound
		}
		return bucket.Delete([]byte(githubID))
	})
}

func (s *BoltUserStore) ListUsers() ([]User, error) {
	var users []User
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			users = append(users, u)
			return nil
		})
	})
	return users, err
}

var _ NewUserStore = (*BoltUserStore)(nil)
