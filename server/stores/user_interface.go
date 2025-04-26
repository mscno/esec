package stores

import (
	"context"
	"errors"
)

type User struct {
	GitHubID  string `json:"github_id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type UserStore interface {
	CreateUser(ctx context.Context, user User) error
	GetUser(ctx context.Context, githubID string) (*User, error)
	UpdateUser(ctx context.Context, githubID string, updateFn func(User) (User, error)) error
	DeleteUser(ctx context.Context, githubID string) error
	ListUsers(ctx context.Context) ([]User, error)
}

var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")
