package stores

import "errors"

type User struct {
	GitHubID  string `json:"github_id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type UserStore interface {
	RegisterUser(user User) error
	UpdateUserPublicKey(githubID, publicKey string) error
	GetUser(githubID string) (*User, error)
}

type NewUserStore interface {
	CreateUser(user User) error
	GetUser(githubID string) (*User, error)
	UpdateUser(githubID string, updateFn func(User) (User, error)) error
	DeleteUser(githubID string) error
	ListUsers() ([]User, error)
}

var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")
