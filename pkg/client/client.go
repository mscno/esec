package client

import (
	"context"
)

type UserId string

func (u UserId) String() string {
	return string(u)
}

type PrivateKeyName string

func (p PrivateKeyName) String() string {
	return string(p)
}

// Client defines the interface for interacting with the esec sync server.
type Client interface {
	SyncUser(ctx context.Context, publicKey string) (err error)
	// CreateProject registers a new project (org/repo) on the sync server.
	CreateProject(ctx context.Context, orgRepo string) error

	GetUserPublicKey(ctx context.Context, usernameOrID UserId) (publicKey, githubID, username string, err error)
	// PushKeysPerUser sends per-recipient encrypted secrets to the sync server for the given project.
	PushKeysPerUser(ctx context.Context, orgRepo string, perUserPayload map[UserId]map[PrivateKeyName]string) error
	// PullKeysPerUser fetches per-recipient encrypted secrets from the sync server for the given project.
	PullKeysPerUser(ctx context.Context, orgRepo string) (map[UserId]map[PrivateKeyName]string, error)
}
