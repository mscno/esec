package stores

import (
	"encoding/json"
	"fmt"
	"go.etcd.io/bbolt"
)

type BoltStore struct {
	db *bbolt.DB
}

var (
	projectsBucket       = []byte("projects")
	perUserSecretsBucket = []byte("per_user_secrets")
)

func NewBoltStore(db *bbolt.DB) (*BoltStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db cannot be nil")
	}
	err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(projectsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(perUserSecretsBucket); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (b *BoltStore) CreateProject(orgRepo string, adminID string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		if bucket.Get([]byte(orgRepo)) != nil {
			return ErrProjectExists
		}
		pd := projectData{
			Admins:  []string{adminID},
			Secrets: map[string]string{},
		}
		val, err := json.Marshal(pd)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(orgRepo), val)
	})
}

func (b *BoltStore) ProjectExists(orgRepo string) bool {
	var exists bool
	b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		exists = bucket.Get([]byte(orgRepo)) != nil
		return nil
	})
	return exists
}

func (b *BoltStore) GetProjectAdmins(orgRepo string) ([]string, error) {
	var pd projectData
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(val, &pd)
	})
	if err != nil {
		return nil, err
	}
	return pd.Admins, nil
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

func (b *BoltStore) GetSecrets(orgRepo string) (map[string]string, error) {
	var pd projectData
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(val, &pd)
	})
	if err != nil {
		return nil, err
	}
	return pd.Secrets, nil
}

func (b *BoltStore) SetSecrets(orgRepo string, secrets map[string]string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(projectsBucket)
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return ErrProjectNotFound
		}
		var pd projectData
		if err := json.Unmarshal(val, &pd); err != nil {
			return err
		}
		pd.Secrets = secrets
		newVal, err := json.Marshal(pd)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(orgRepo), newVal)
	})
}

func (b *BoltStore) GetPerUserSecrets(orgRepo string) (map[string]map[string]string, error) {
	var result map[string]map[string]string
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(perUserSecretsBucket)
		val := bucket.Get([]byte(orgRepo))
		if val == nil {
			return ErrProjectNotFound
		}
		return json.Unmarshal(val, &result)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (b *BoltStore) SetPerUserSecrets(orgRepo string, secrets map[string]map[string]string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(perUserSecretsBucket)
		val, err := json.Marshal(secrets)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(orgRepo), val)
	})
}

var _ ProjectStore = (*BoltStore)(nil)
