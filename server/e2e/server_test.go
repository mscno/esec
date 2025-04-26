package e2e

import (
	"context"
	"github.com/mscno/esec/pkg/cloudmodel"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/middleware"
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"

	"connectrpc.com/connect"

	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/server/stores"
)

func mockUserHasRoleInRepo(token string, orgRepo cloudmodel.OrgRepo, role string) bool {
	if token == "testtoken" && orgRepo == "foo/bar" {
		return true
	}
	return false
}

func mockTokenValidator(token string) (middleware.GithubUser, bool) {
	if token == "testtoken" {
		return middleware.GithubUser{Login: "testuser", ID: 42}, true
	}
	return middleware.GithubUser{}, false
}
func setupTestServer() *server.Server {
	store := stores.NewInMemoryProjectStore()
	userStore := stores.NewInMemoryUserStore()
	logger := slog.Default()
	return server.NewServer(store, userStore, logger, mockUserHasRoleInRepo)
}

func setUserInContext(ctx context.Context, user middleware.GithubUser) context.Context {
	return context.WithValue(ctx, "user", user)
}

func TestCreateProject(t *testing.T) {
	s := setupTestServer()
	ctx := context.Background()
	ctx = setUserInContext(ctx, middleware.GithubUser{Login: "testuser", ID: 42, Token: "testtoken"})
	// Simulate user ID via header
	req := connect.NewRequest(&esecpb.CreateProjectRequest{OrgRepo: "foo/bar"})
	req.Header().Set("x-github-user-id", "42")
	resp, err := s.CreateProject(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "project registered", resp.Msg.Status)
	require.Equal(t, "foo/bar", resp.Msg.Project)
}

func TestRegisterUser(t *testing.T) {
	s := setupTestServer()
	ctx := context.Background()
	ctx = setUserInContext(ctx, middleware.GithubUser{Login: "testuser", ID: 42, Token: "testtoken"})

	req := connect.NewRequest(&esecpb.RegisterUserRequest{
		PublicKey: "key123",
	})
	resp, err := s.RegisterUser(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "user registered", resp.Msg.Status)
}

func TestRegisterUser_Duplicate(t *testing.T) {
	s := setupTestServer()
	ctx := context.Background()
	ctx = setUserInContext(ctx, middleware.GithubUser{Login: "testuser", ID: 42, Token: "testtoken"})

	reg := connect.NewRequest(&esecpb.RegisterUserRequest{
		PublicKey: "key123",
	})
	_, err := s.RegisterUser(ctx, reg)
	require.NoError(t, err)
	_, err = s.RegisterUser(ctx, reg)
	require.Error(t, err)
}

func TestGetUserPublicKey(t *testing.T) {
	s := setupTestServer()
	ctx := context.Background()
	ctx = setUserInContext(ctx, middleware.GithubUser{Login: "testuser", ID: 42, Token: "testtoken"})

	reg := connect.NewRequest(&esecpb.RegisterUserRequest{
		PublicKey: "key123",
	})
	_, err := s.RegisterUser(ctx, reg)
	require.NoError(t, err)
	resp, err := s.GetUserPublicKey(ctx, connect.NewRequest(&esecpb.GetUserPublicKeyRequest{GithubId: "42"}))
	require.NoError(t, err)
	require.Equal(t, "key123", resp.Msg.PublicKey)
}

func TestSetAndGetPerUserSecrets(t *testing.T) {
	s := setupTestServer()
	ctx := context.Background()
	ctx = setUserInContext(ctx, middleware.GithubUser{Login: "testuser", ID: 42, Token: "testtoken"})

	reg := connect.NewRequest(&esecpb.RegisterUserRequest{
		PublicKey: "key123",
	})
	_, err := s.RegisterUser(ctx, reg)
	require.NoError(t, err)
	// Create project
	projReq := connect.NewRequest(&esecpb.CreateProjectRequest{OrgRepo: "foo/bar"})
	_, err = s.CreateProject(ctx, projReq)
	require.NoError(t, err)
	// Set secrets
	setReq := connect.NewRequest(&esecpb.SetPerUserSecretsRequest{
		OrgRepo: "foo/bar",
		Secrets: map[string]*esecpb.SecretMap{
			"42": {Secrets: map[string]string{"a": "b"}},
		},
	})
	_, err = s.SetPerUserSecrets(ctx, setReq)
	require.NoError(t, err)
	// Get secrets
	getReq := connect.NewRequest(&esecpb.GetPerUserSecretsRequest{OrgRepo: "foo/bar"})
	resp, err := s.GetPerUserSecrets(ctx, getReq)
	require.NoError(t, err)
	secrets := resp.Msg.Secrets["42"].Secrets
	require.Equal(t, "b", secrets["a"])
}
