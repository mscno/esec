package client

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
)

// ConnectClient implements the Client interface using connectrpc
// It is the modern gRPC/ConnectRPC-based client for the esec sync server.
type ConnectClient struct {
	client esecpbconnect.EsecServiceClient
	logger *slog.Logger
}

func (c *ConnectClient) SyncUser(ctx context.Context, publicKey string) error {
	req := connect.NewRequest(&esecpb.RegisterUserRequest{PublicKey: publicKey})
	_, err := c.client.RegisterUser(ctx, req)
	return err
}

// ClientConfig holds configuration for creating a new APIClient.
type ClientConfig struct {
	ServerURL string
	AuthToken string
	Logger    *slog.Logger
}

func NewConnectClient(config ClientConfig) *ConnectClient {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
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
			req.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, req)
		})
	}
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
	for userID, secmap := range resp.Msg.Secrets {
		for keyName, secret := range secmap.Secrets {
			userIdTyped := UserId(userID)
			keyTyped := PrivateKeyName(keyName)
			if _, ok := result[userIdTyped]; ok {
				result[userIdTyped][keyTyped] = secret
			} else {
				result[userIdTyped] = map[PrivateKeyName]string{
					keyTyped: secret,
				}
			}
		}
	}
	return result, nil
}

var _ Client = (*ConnectClient)(nil)
