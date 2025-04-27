package stores

import (
	"context"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/model"
)

type InMemoryUserStore struct {
	users map[model.UserId]model.User
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[model.UserId]model.User)}
}

func (s *InMemoryUserStore) CreateUser(ctx context.Context, user model.User) error {
	if _, exists := s.users[user.GitHubID]; exists {
		return server.ErrUserExists
	}
	s.users[user.GitHubID] = user
	return nil
}

func (s *InMemoryUserStore) GetUser(ctx context.Context, githubID model.UserId) (*model.User, error) {
	u, ok := s.users[githubID]
	if !ok {
		return nil, server.ErrUserNotFound
	}
	return &u, nil
}

func (s *InMemoryUserStore) UpdateUser(ctx context.Context, githubID model.UserId, updateFn func(model.User) (model.User, error)) error {
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

func (s *InMemoryUserStore) DeleteUser(ctx context.Context, githubID model.UserId) error {
	if _, ok := s.users[githubID]; !ok {
		return server.ErrUserNotFound
	}
	delete(s.users, githubID)
	return nil
}

func (s *InMemoryUserStore) ListUsers(ctx context.Context) ([]model.User, error) {
	var out []model.User
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}

var _ server.UserStore = (*InMemoryUserStore)(nil)
