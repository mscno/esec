package stores

import "context"

type InMemoryUserStore struct {
	users map[string]User
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[string]User)}
}

func (s *InMemoryUserStore) CreateUser(ctx context.Context, user User) error {
	if _, exists := s.users[user.GitHubID]; exists {
		return ErrUserExists
	}
	s.users[user.GitHubID] = user
	return nil
}

func (s *InMemoryUserStore) GetUser(ctx context.Context, githubID string) (*User, error) {
	u, ok := s.users[githubID]
	if !ok {
		return nil, ErrUserNotFound
	}
	return &u, nil
}

func (s *InMemoryUserStore) UpdateUser(ctx context.Context, githubID string, updateFn func(User) (User, error)) error {
	u, ok := s.users[githubID]
	if !ok {
		return ErrUserNotFound
	}
	updated, err := updateFn(u)
	if err != nil {
		return err
	}
	s.users[githubID] = updated
	return nil
}

func (s *InMemoryUserStore) DeleteUser(ctx context.Context, githubID string) error {
	if _, ok := s.users[githubID]; !ok {
		return ErrUserNotFound
	}
	delete(s.users, githubID)
	return nil
}

func (s *InMemoryUserStore) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}

var _ UserStore = (*InMemoryUserStore)(nil)
