package client

import (
	"context"

	esecpb "github.com/mscno/esec/gen/proto/go/esec"
)

// ... (UserId, PrivateKeyName remain same) ...
type UserId string

func (u UserId) String() string {
	return string(u)
}

type PrivateKeyName string

func (p PrivateKeyName) String() string {
	return string(p)
}

type Client interface {
	InitiateSession(ctx context.Context, githubUserToken string) (sessionToken string, expiresAtUnix int64, err error)

	SyncUser(ctx context.Context, publicKey string) (err error)
	CreateProject(ctx context.Context, orgRepo string) error
	GetUserPublicKey(ctx context.Context, usernameOrID UserId) (publicKey, githubID, username string, err error)
	PushKeysPerUser(ctx context.Context, orgRepo string, perUserPayload map[UserId]map[PrivateKeyName]string) error
	PullKeysPerUser(ctx context.Context, orgRepo string) (map[UserId]map[PrivateKeyName]string, error)

	CreateOrganization(ctx context.Context, name string) (*esecpb.Organization, error)
	ListOrganizations(ctx context.Context) ([]*esecpb.Organization, error)
	GetOrganization(ctx context.Context, id string) (*esecpb.Organization, error)
	DeleteOrganization(ctx context.Context, id string) (string, error)

	CheckInstallation(ctx context.Context, targetName string, isOrg bool) (installed bool, installationID string, message string, err error)
}
