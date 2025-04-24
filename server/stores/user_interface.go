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

var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")
