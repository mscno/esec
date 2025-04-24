package server

import (
	"connectrpc.com/connect"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
	"github.com/mscno/esec/server/middleware"
	"github.com/mscno/esec/server/stores"
	"log/slog"
	"net/http"
)

// Server implements esecpbconnect.EsecServiceHandler
// It adapts the Handler logic for gRPC/protobuf
// Add dependencies as in Handler
type Server struct {
	Store             stores.ProjectStore
	UserStore         stores.UserStore
	Logger            *slog.Logger
	userHasRoleInRepo UserHasRoleInRepoFunc
}

type UserHasRoleInRepoFunc func(token, orgRepo, role string) bool

func NewServer(store stores.ProjectStore, userStore stores.UserStore, logger *slog.Logger, userHasRoleInRepo UserHasRoleInRepoFunc) *Server {
	if userHasRoleInRepo == nil {
		userHasRoleInRepo = defaultUserHasRoleInRepo
	}
	return &Server{
		Store:             store,
		UserStore:         userStore,
		Logger:            logger,
		userHasRoleInRepo: userHasRoleInRepo,
	}
}

var _ esecpbconnect.EsecServiceHandler = (*Server)(nil)

func (s *Server) CreateProject(ctx context.Context, request *connect.Request[esecpb.CreateProjectRequest]) (*connect.Response[esecpb.CreateProjectResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		slog.Error("user info missing from context")
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	orgRepo := request.Msg.GetOrgRepo()
	if orgRepo == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepo); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}
	creatorID := fmt.Sprintf("%d", ghuser.ID)
	if creatorID == "" || creatorID == "0" {
		s.Logger.Error("could not determine creator's github id")
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("could not determine creator's github id"))
	}

	if !s.userHasRoleInRepo(ghuser.Token, request.Msg.OrgRepo, "admin") {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("access to %s denied", request.Msg.OrgRepo))
	}
	if err := s.Store.CreateProject(orgRepo, creatorID); err != nil {
		if errors.Is(err, stores.ErrProjectExists) {
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		}
		s.Logger.Error("failed to create project", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create project: %w", err))
	}
	return connect.NewResponse(&esecpb.CreateProjectResponse{
		Status:  "project registered",
		Project: orgRepo,
	}), nil
}

func (s *Server) RegisterUser(ctx context.Context, request *connect.Request[esecpb.RegisterUserRequest]) (*connect.Response[esecpb.RegisterUserResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		slog.Error("user info missing from context")
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	user := stores.User{
		GitHubID:  fmt.Sprintf("%d", ghuser.ID),
		Username:  ghuser.Login,
		PublicKey: request.Msg.GetPublicKey(),
	}
	if user.GitHubID == "" || user.Username == "" || user.PublicKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing user fields"))
	}
	if _, err := s.UserStore.GetUser(user.GitHubID); err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}
	if err := s.UserStore.RegisterUser(user); err != nil {
		s.Logger.Error("failed to register user", "github_id", user.GitHubID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register user: %w", err))
	}
	_ = s.UserStore.UpdateUserPublicKey(user.GitHubID, user.PublicKey)
	return connect.NewResponse(&esecpb.RegisterUserResponse{
		Status: "user registered",
	}), nil
}

func (s *Server) GetUserPublicKey(ctx context.Context, request *connect.Request[esecpb.GetUserPublicKeyRequest]) (*connect.Response[esecpb.GetUserPublicKeyResponse], error) {
	githubID := request.Msg.GetGithubId()
	if githubID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing github_id"))
	}
	user, err := s.UserStore.GetUser(githubID)
	if err != nil {
		if err.Error() == "user not found" {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found"))
		}
		s.Logger.Error("failed to get user", "github_id", githubID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}
	return connect.NewResponse(&esecpb.GetUserPublicKeyResponse{
		GithubId:  user.GitHubID,
		Username:  user.Username,
		PublicKey: user.PublicKey,
	}), nil
}

func (s *Server) SetPerUserSecrets(ctx context.Context, request *connect.Request[esecpb.SetPerUserSecretsRequest]) (*connect.Response[esecpb.SetPerUserSecretsResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	orgRepo := request.Msg.GetOrgRepo()
	if orgRepo == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepo); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}
	if !s.Store.ProjectExists(orgRepo) {
		s.Logger.Error("project does not exist or you do not have access", "orgRepo", orgRepo)
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project does not exist or you do not have access"))
	}
	if !s.Store.IsProjectAdmin(orgRepo, fmt.Sprintf("%d", ghuser.ID)) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("only project admins may share secrets for this project"))
	}
	secrets := make(map[string]map[string]string)
	for userID, secretMap := range request.Msg.GetSecrets() {
		secrets[userID] = secretMap.Secrets
	}
	if err := s.Store.SetPerUserSecrets(orgRepo, secrets); err != nil {
		s.Logger.Error("failed to store per-user secrets", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store per-user secrets: %w", err))
	}
	return connect.NewResponse(&esecpb.SetPerUserSecretsResponse{Status: "ok"}), nil
}

func (s *Server) GetPerUserSecrets(ctx context.Context, request *connect.Request[esecpb.GetPerUserSecretsRequest]) (*connect.Response[esecpb.GetPerUserSecretsResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	orgRepo := request.Msg.GetOrgRepo()
	if orgRepo == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepo); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}
	if !s.Store.ProjectExists(orgRepo) {
		s.Logger.Error("project does not exist or you do not have access", "orgRepo", orgRepo)
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project does not exist or you do not have access"))
	}
	if !s.Store.IsProjectAdmin(orgRepo, fmt.Sprintf("%d", ghuser.ID)) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("only project admins may share secrets for this project"))
	}
	secrets, err := s.Store.GetPerUserSecrets(orgRepo)
	if err != nil {
		if err.Error() == "project not found" {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project not found"))
		}
		s.Logger.Error("failed to get per-user secrets", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get per-user secrets: %w", err))
	}
	resp := &esecpb.GetPerUserSecretsResponse{Secrets: map[string]*esecpb.SecretMap{}}
	for userID, secretMap := range secrets {
		resp.Secrets[userID] = &esecpb.SecretMap{Secrets: secretMap}
	}
	return connect.NewResponse(resp), nil
}

// userHasRoleInRepo checks if the given GitHub token has a role in the given org/repo.
func defaultUserHasRoleInRepo(token, orgRepo string, role string) bool {
	if token == "" || orgRepo == "" || role == "" {
		return false
	}

	githubAPIURL := "https://api.github.com/repos/" + orgRepo
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	slog.Info("checking role in repo", "orgRepo", orgRepo, "role", role)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		slog.Warn("repo not found", "orgRepo", orgRepo)
		return false
	}

	if resp.StatusCode == http.StatusForbidden {
		slog.Warn("access to repo denied", "orgRepo", orgRepo)
		return false
	}

	var ghResp struct {
		Permissions struct {
			Admin bool `json:"admin"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return false
	}

	switch role {
	case "admin":
		return ghResp.Permissions.Admin
	case "read":
		return resp.StatusCode == http.StatusOK
	default:
		return false
	}
}
