package stores

import (
	"context"
	"encoding/json"
	"github.com/mscno/esec/pkg/cloudmodel"
	"github.com/mscno/esec/server"
	"go.etcd.io/bbolt"
)

type BoltUserStore struct {
	db *bbolt.DB
}

func NewBoltUserStore(db *bbolt.DB) *BoltUserStore {
	return &BoltUserStore{db: db}
}

var usersBucket = []byte("users")

func (s *BoltUserStore) CreateUser(ctx context.Context, user cloudmodel.User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(usersBucket)
		if err != nil {
			return err
		}
		if bucket.Get([]byte(user.GitHubID)) != nil {
			return server.ErrUserExists
		}
		data, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.GitHubID), data)
	})
}

func (s *BoltUserStore) GetUser(ctx context.Context, githubID cloudmodel.UserId) (*cloudmodel.User, error) {
	var user cloudmodel.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return server.ErrUserNotFound
		}
		val := bucket.Get([]byte(githubID))
		if val == nil {
			return server.ErrUserNotFound
		}
		return json.Unmarshal(val, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *BoltUserStore) UpdateUser(ctx context.Context, githubID cloudmodel.UserId, updateFn func(cloudmodel.User) (cloudmodel.User, error)) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return server.ErrUserNotFound
		}
		val := bucket.Get([]byte(githubID))
		if val == nil {
			return server.ErrUserNotFound
		}
		var user cloudmodel.User
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

func (s *BoltUserStore) DeleteUser(ctx context.Context, githubID cloudmodel.UserId) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return server.ErrUserNotFound
		}
		if bucket.Get([]byte(githubID)) == nil {
			return server.ErrUserNotFound
		}
		return bucket.Delete([]byte(githubID))
	})
}

func (s *BoltUserStore) ListUsers(ctx context.Context) ([]cloudmodel.User, error) {
	var users []cloudmodel.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var u cloudmodel.User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			users = append(users, u)
			return nil
		})
	})
	return users, err
}

var _ server.UserStore = (*BoltUserStore)(nil)
