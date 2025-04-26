package stores

import (
	"context"
	"github.com/mscno/esec/pkg/cloudmodel"
	"github.com/mscno/esec/server"
)

type InMemoryUserStore struct {
	users map[cloudmodel.UserId]cloudmodel.User
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[cloudmodel.UserId]cloudmodel.User)}
}

func (s *InMemoryUserStore) CreateUser(ctx context.Context, user cloudmodel.User) error {
	if _, exists := s.users[user.GitHubID]; exists {
		return server.ErrUserExists
	}
	s.users[user.GitHubID] = user
	return nil
}

func (s *InMemoryUserStore) GetUser(ctx context.Context, githubID cloudmodel.UserId) (*cloudmodel.User, error) {
	u, ok := s.users[githubID]
	if !ok {
		return nil, server.ErrUserNotFound
	}
	return &u, nil
}

func (s *InMemoryUserStore) UpdateUser(ctx context.Context, githubID cloudmodel.UserId, updateFn func(cloudmodel.User) (cloudmodel.User, error)) error {
	u, ok := s.users[githubID]
	if !ok {
		return server.ErrUserNotFound
	}
	updated, err := updateFn(u)
	if err != nil {
		return err
	}
	s.users[githubID] = updated
	return nil
}

func (s *InMemoryUserStore) DeleteUser(ctx context.Context, githubID cloudmodel.UserId) error {
	if _, ok := s.users[githubID]; !ok {
		return server.ErrUserNotFound
	}
	delete(s.users, githubID)
	return nil
}

func (s *InMemoryUserStore) ListUsers(ctx context.Context) ([]cloudmodel.User, error) {
	var out []cloudmodel.User
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}

var _ server.UserStore = (*InMemoryUserStore)(nil)
