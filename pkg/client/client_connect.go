// esec/pkg/client/client_connect.go
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
)

// ... (ConnectClient struct and NewConnectClient remain similar) ...
type ConnectClient struct {
	client esecpbconnect.EsecServiceClient
	logger *slog.Logger
}

type ClientConfig struct {
	ServerURL string
	AuthToken string // This will now be the app-managed session token
	Logger    *slog.Logger
}

func NewConnectClient(config ClientConfig) *ConnectClient {
	if config.Logger == nil {
		config.Logger = slog.Default() // Or your preferred default logger
	}

	httpClient := &http.Client{Timeout: 30 * time.Second} // General client timeout

	// The interceptor now adds the app-managed session token
	client := esecpbconnect.NewEsecServiceClient(httpClient, config.ServerURL,
		connect.WithClientOptions(connect.WithInterceptors(authIntercepter(config.AuthToken))))
	return &ConnectClient{client: client, logger: config.Logger}
}

func authIntercepter(token string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			// Only add auth header if token is present.
			// InitiateSession will be called without this token initially.
			if token != "" {
				req.Header().Set("Authorization", "Bearer "+token)
			}
			return next(ctx, req)
		})
	}
}

// InitiateSession calls the server to exchange a GitHub user token for an app session token.
// Note: This method is special. The ConnectClient's `AuthToken` (session token)
// should NOT be set in the header for this specific call. The `authIntercepter`
// needs to be aware or this client needs a way to make a call without the default interceptor.
// For simplicity, we'll assume the interceptor adds the token if present, and for InitiateSession,
// the ConnectClient is initialized with an EMPTY AuthToken. The CLI will then re-initialize
// the client with the new session token.
func (c *ConnectClient) InitiateSession(ctx context.Context, githubUserToken string) (string, int64, error) {
	req := connect.NewRequest(&esecpb.InitiateSessionRequest{
		GithubUserToken: githubUserToken,
	})
	// This call should NOT send the existing session token, if any.
	// The interceptor logic needs to handle this, or we need a separate http client for this call.
	// A simple way: the CLI creates a temporary client with NO AuthToken for this call.
	// Or, the interceptor checks the procedure name.
	// For now, assuming the interceptor is simple and adds AuthToken if configured.
	// The CLI will handle creating a client without a session token for this call.

	resp, err := c.client.InitiateSession(ctx, req)
	if err != nil {
		c.logger.ErrorContext(ctx, "InitiateSession request failed", "error", err)
		return "", 0, fmt.Errorf("InitiateSession failed: %w", err)
	}
	return resp.Msg.GetSessionToken(), resp.Msg.GetExpiresAtUnix(), nil
}

// SyncUser, CreateProject, etc. will now be authenticated by the app session token
// set in the client's AuthToken via the interceptor.
// ... (SyncUser, CreateProject, GetUserPublicKey, PushKeysPerUser, PullKeysPerUser methods remain structurally similar) ...
func (c *ConnectClient) SyncUser(ctx context.Context, publicKey string) error {
	req := connect.NewRequest(&esecpb.RegisterUserRequest{PublicKey: publicKey})
	_, err := c.client.RegisterUser(ctx, req)
	return err
}

func (c *ConnectClient) CreateProject(ctx context.Context, orgRepo string) error {
	req := connect.NewRequest(&esecpb.CreateProjectRequest{OrgRepo: orgRepo})
	_, err := c.client.CreateProject(ctx, req)
	return err
}

func (c *ConnectClient) GetUserPublicKey(ctx context.Context, usernameOrID UserId) (publicKey, githubID, username string, err error) {
	req := connect.NewRequest(&esecpb.GetUserPublicKeyRequest{GithubId: usernameOrID.String()})
	resp, err := c.client.GetUserPublicKey(ctx, req)
	if err != nil {
		return "", "", "", err
	}
	return resp.Msg.PublicKey, resp.Msg.GithubId, resp.Msg.Username, nil
}

func (c *ConnectClient) PushKeysPerUser(ctx context.Context, orgRepo string, perUserPayload map[UserId]map[PrivateKeyName]string) error {
	secrets := map[string]*esecpb.SecretMap{}
	for userId, secmap := range perUserPayload {
		var secretMap = &esecpb.SecretMap{
			Secrets: make(map[string]string),
		}
		for key, cipher := range secmap {
			secretMap.Secrets[key.String()] = cipher
		}
		secrets[userId.String()] = secretMap
	}
	req := connect.NewRequest(&esecpb.SetPerUserSecretsRequest{
		OrgRepo: orgRepo,
		Secrets: secrets,
	})
	_, err := c.client.SetPerUserSecrets(ctx, req)
	return err
}

func (c *ConnectClient) PullKeysPerUser(ctx context.Context, orgRepo string) (map[UserId]map[PrivateKeyName]string, error) {
	req := connect.NewRequest(&esecpb.GetPerUserSecretsRequest{OrgRepo: orgRepo})
	resp, err := c.client.GetPerUserSecrets(ctx, req)
	if err != nil {
		return nil, err
	}
	result := make(map[UserId]map[PrivateKeyName]string)
	for userID, secretMap := range resp.Msg.Secrets {
		userIDTyped := UserId(userID)
		if _, ok := result[userIDTyped]; !ok {
			result[userIDTyped] = make(map[PrivateKeyName]string)
		}
		for keyName, secret := range secretMap.Secrets {
			keyTyped := PrivateKeyName(keyName)
			result[userIDTyped][keyTyped] = secret
		}
	}
	return result, nil
}

// --- Organization Methods (remain structurally similar) ---
func (c *ConnectClient) CreateOrganization(ctx context.Context, name string) (*esecpb.Organization, error) {
	req := &esecpb.CreateOrganizationRequest{
		Name: name,
	}
	resp, err := c.client.CreateOrganization(ctx, connect.NewRequest(req))
	if err != nil {
		c.logger.Error("CreateOrganization request failed", "error", err)
		return nil, fmt.Errorf("CreateOrganization failed: %w", err)
	}
	return resp.Msg.GetOrganization(), nil
}

func (c *ConnectClient) ListOrganizations(ctx context.Context) ([]*esecpb.Organization, error) {
	req := &esecpb.ListOrganizationsRequest{}
	resp, err := c.client.ListOrganizations(ctx, connect.NewRequest(req))
	if err != nil {
		c.logger.Error("ListOrganizations request failed", "error", err)
		return nil, fmt.Errorf("ListOrganizations failed: %w", err)
	}
	return resp.Msg.GetOrganizations(), nil
}

func (c *ConnectClient) GetOrganization(ctx context.Context, id string) (*esecpb.Organization, error) {
	req := &esecpb.GetOrganizationRequest{
		Id: id,
	}
	resp, err := c.client.GetOrganization(ctx, connect.NewRequest(req))
	if err != nil {
		c.logger.Error("GetOrganization request failed", "id", id, "error", err)
		return nil, fmt.Errorf("GetOrganization failed: %w", err)
	}
	return resp.Msg.GetOrganization(), nil
}

func (c *ConnectClient) DeleteOrganization(ctx context.Context, id string) (string, error) {
	req := &esecpb.DeleteOrganizationRequest{
		Id: id,
	}
	resp, err := c.client.DeleteOrganization(ctx, connect.NewRequest(req))
	if err != nil {
		c.logger.Error("DeleteOrganization request failed", "id", id, "error", err)
		return "", fmt.Errorf("DeleteOrganization failed: %w", err)
	}
	return resp.Msg.GetStatus(), nil
}

// CheckInstallation calls the server to check GitHub App installation status.
func (c *ConnectClient) CheckInstallation(ctx context.Context, targetName string, isOrg bool) (bool, string, string, error) {
	req := &esecpb.CheckInstallationRequest{}
	if isOrg {
		req.Target = &esecpb.CheckInstallationRequest_OrganizationName{OrganizationName: targetName}
	} else {
		if !strings.Contains(targetName, "/") {
			return false, "", "", fmt.Errorf("repository name must be in 'owner/repo' format")
		}
		req.Target = &esecpb.CheckInstallationRequest_RepositoryName{RepositoryName: targetName}
	}

	resp, err := c.client.CheckInstallation(ctx, connect.NewRequest(req))
	if err != nil {
		c.logger.ErrorContext(ctx, "CheckInstallation request failed", "target", targetName, "isOrg", isOrg, "error", err)
		return false, "", "", fmt.Errorf("CheckInstallation failed: %w", err)
	}
	return resp.Msg.GetInstalled(), resp.Msg.GetInstallationId(), resp.Msg.GetMessage(), nil
}

var _ Client = (*ConnectClient)(nil)
