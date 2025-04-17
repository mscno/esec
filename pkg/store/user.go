package store

import "fmt"

type User struct {
	GitHubID  string
	Username  string
	PublicKey string
}

type UserStore interface {
	RegisterUser(user User) error
	UpdateUserPublicKey(githubID, publicKey string) error
	GetUser(githubID string) (*User, error)
}

type memoryUserStore struct {
	users map[string]*User // githubID -> User
}

func NewMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{users: make(map[string]*User)}
}

func (s *memoryUserStore) RegisterUser(user User) error {
	if _, exists := s.users[user.GitHubID]; exists {
		return nil // Already exists
	}
	s.users[user.GitHubID] = &user
	return nil
}

func (s *memoryUserStore) UpdateUserPublicKey(githubID, publicKey string) error {
	u, ok := s.users[githubID]
	if !ok {
		return ErrUserNotFound
	}
	u.PublicKey = publicKey
	return nil
}

func (s *memoryUserStore) GetUser(githubID string) (*User, error) {
	u, ok := s.users[githubID]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

var ErrUserNotFound = fmt.Errorf("user not found")
