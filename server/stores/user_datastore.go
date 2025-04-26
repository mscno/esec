package stores

import (
	"context"
	"errors"

	"cloud.google.com/go/datastore"
)

const userKind = "User"

type UserDataStore struct {
	client *datastore.Client
}

func NewUserDataStore(ctx context.Context, client *datastore.Client) *UserDataStore {
	return &UserDataStore{client: client}
}

// Close closes the underlying datastore client.
func (s *UserDataStore) Close() error {
	return s.client.Close()
}

func (s *UserDataStore) userKey(githubID string) *datastore.Key {
	return datastore.NameKey(userKind, githubID, nil)
}

func (s *UserDataStore) CreateUser(ctx context.Context, user User) error {
	key := s.userKey(user.GitHubID)
	// Check if user already exists
	var existingUser User
	err := s.client.Get(ctx, key, &existingUser)
	if err == nil {
		return ErrUserExists
	}
	if !errors.Is(err, datastore.ErrNoSuchEntity) {
		return err // Some other error occurred
	}

	// User does not exist, create them
	_, err = s.client.Put(ctx, key, &user)
	return err
}

func (s *UserDataStore) GetUser(ctx context.Context, githubID string) (*User, error) {
	key := s.userKey(githubID)
	var user User
	err := s.client.Get(ctx, key, &user)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserDataStore) UpdateUser(ctx context.Context, githubID string, updateFn func(user User) (User, error)) error {
	key := s.userKey(githubID)
	tx, err := s.client.NewTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() // Rollback if commit fails or anything goes wrong

	var user User
	err = tx.Get(key, &user)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return ErrUserNotFound
	}
	if err != nil {
		return err
	}

	updatedUser, err := updateFn(user)
	if err != nil {
		return err // Error from the update function itself
	}

	// Ensure GitHubID hasn't changed
	if updatedUser.GitHubID != githubID {
		return errors.New("cannot change GitHubID during update")
	}

	_, err = tx.Put(key, &updatedUser)
	if err != nil {
		return err
	}

	_, err = tx.Commit()
	return err
}

func (s *UserDataStore) DeleteUser(ctx context.Context, githubID string) error {
	key := s.userKey(githubID)
	err := s.client.Delete(ctx, key)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		// Consider if deleting a non-existent user is an error or idempotent
		return ErrUserNotFound // Or return nil if idempotent deletion is desired
	}
	return err
}

func (s *UserDataStore) ListUsers(ctx context.Context) ([]User, error) {
	var users []User
	query := datastore.NewQuery(userKind)
	_, err := s.client.GetAll(ctx, query, &users)
	if err != nil {
		return nil, err
	}
	// If users is nil (GetAll returns nil slice on no results), return empty slice
	if users == nil {
		return []User{}, nil
	}
	return users, nil
}

// Compile-time check to ensure UserDataStore implements UserStore
var _ UserStore = (*UserDataStore)(nil)
