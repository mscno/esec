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
	model "github.com/mscno/esec/server/model"
	"log/slog"
	"net/http"
)

type UserStore interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUser(ctx context.Context, githubID model.UserId) (*model.User, error)
	UpdateUser(ctx context.Context, githubID model.UserId, updateFn func(model.User) (model.User, error)) error
	DeleteUser(ctx context.Context, githubID model.UserId) error
	ListUsers(ctx context.Context) ([]model.User, error)
}

var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")

type ProjectStore interface {
	CreateProject(ctx context.Context, project model.Project) error
	GetProject(ctx context.Context, orgRepo model.OrgRepo) (model.Project, error)
	UpdateProject(ctx context.Context, orgRepo model.OrgRepo, updateFn func(project model.Project) (model.Project, error)) error
	ListProjects(ctx context.Context) ([]model.Project, error)
	DeleteProject(ctx context.Context, orgRepo model.OrgRepo) error

	// New methods for handling secrets
	SetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userId model.UserId, secrets map[model.PrivateKeyName]string) error
	GetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userId model.UserId) (map[model.PrivateKeyName]string, error)
	GetAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) (map[model.UserId]map[model.PrivateKeyName]string, error)
	DeleteProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userID model.UserId) error
	DeleteAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) error
}

var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")

// Server implements esecpbconnect.EsecServiceHandler
// It adapts the Handler logic for gRPC/protobuf
// Add dependencies as in Handler
type Server struct {
	Store             ProjectStore
	UserStore         UserStore
	Logger            *slog.Logger
	userHasRoleInRepo UserHasRoleInRepoFunc
}

type UserHasRoleInRepoFunc func(token string, orgRepo model.OrgRepo, role string) bool

func NewServer(store ProjectStore, userStore UserStore, logger *slog.Logger, userHasRoleInRepo UserHasRoleInRepoFunc) *Server {
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

	if !s.userHasRoleInRepo(ghuser.Token, model.OrgRepo(orgRepo), "admin") {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("access to %s denied", request.Msg.OrgRepo))
	}

	project := model.Project{
		OrgRepo: model.OrgRepo(orgRepo),
	}
	if err := s.Store.CreateProject(ctx, project); err != nil {
		if errors.Is(err, ErrProjectExists) {
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
	user := model.User{
		GitHubID:  model.UserId(fmt.Sprintf("%d", ghuser.ID)),
		Username:  ghuser.Login,
		PublicKey: request.Msg.GetPublicKey(),
	}
	if user.GitHubID == "" || user.Username == "" || user.PublicKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing user fields"))
	}
	if _, err := s.UserStore.GetUser(ctx, user.GitHubID); err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}
	if err := s.UserStore.CreateUser(ctx, user); err != nil {
		s.Logger.Error("failed to register user", "github_id", user.GitHubID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register user: %w", err))
	}
	return connect.NewResponse(&esecpb.RegisterUserResponse{
		Status: "user registered",
	}), nil
}

func (s *Server) GetUserPublicKey(ctx context.Context, request *connect.Request[esecpb.GetUserPublicKeyRequest]) (*connect.Response[esecpb.GetUserPublicKeyResponse], error) {
	githubID := request.Msg.GetGithubId()
	if githubID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing github_id"))
	}
	user, err := s.UserStore.GetUser(ctx, model.UserId(githubID))
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found"))
		}
		s.Logger.Error("failed to get user", "github_id", githubID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}
	return connect.NewResponse(&esecpb.GetUserPublicKeyResponse{
		GithubId:  user.GitHubID.String(),
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
	_, err := s.Store.GetProject(ctx, model.OrgRepo(orgRepo))
	if err != nil {
		s.Logger.Error("project not found", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project not found: %w", err))
	}

	if !s.userHasRoleInRepo(ghuser.Token, model.OrgRepo(orgRepo), "admin") {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("only project admins may share secrets for this project"))
	}

	secrets := make(map[model.UserId]map[model.PrivateKeyName]string)
	for userId, secretMap := range request.Msg.GetSecrets() {
		userIdTyped := model.UserId(userId)
		for key, ciphertext := range secretMap.GetSecrets() {
			keyTyped := model.PrivateKeyName(key)
			if _, ok := secrets[userIdTyped][keyTyped]; ok {
				secrets[userIdTyped][keyTyped] = ciphertext
			} else {
				secrets[userIdTyped] = make(map[model.PrivateKeyName]string)
				secrets[userIdTyped][keyTyped] = ciphertext
			}
		}
	}

	for userId, userSecrets := range secrets {
		err := s.Store.SetProjectUserSecrets(ctx, model.OrgRepo(orgRepo), userId, userSecrets)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to set project user secrets: %w", err))
		}
	}

	return connect.NewResponse(&esecpb.SetPerUserSecretsResponse{Status: "ok"}), nil
}

func (s *Server) GetPerUserSecrets(ctx context.Context, request *connect.Request[esecpb.GetPerUserSecretsRequest]) (*connect.Response[esecpb.GetPerUserSecretsResponse], error) {
	_, ok := ctx.Value("user").(middleware.GithubUser)
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

	_, err := s.Store.GetProject(ctx, model.OrgRepo(orgRepo))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project not found: %w", err))
	}

	secrets, err := s.Store.GetAllProjectUserSecrets(ctx, model.OrgRepo(orgRepo))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store per-user secrets: %w", err))
	}
	resp := &esecpb.GetPerUserSecretsResponse{Secrets: map[string]*esecpb.SecretMap{}}
	for userID, secretMap := range secrets {
		userSecrets := esecpb.SecretMap{
			Secrets: make(map[string]string, len(secrets)),
		}
		for key, cipher := range secretMap {
			userSecrets.Secrets[string(key)] = cipher
		}
		resp.Secrets[string(userID)] = &userSecrets
	}
	return connect.NewResponse(resp), nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

// userHasRoleInRepo checks if the given GitHub token has a role in the given org/repo.
func defaultUserHasRoleInRepo(token string, orgRepo model.OrgRepo, role string) bool {
	if token == "" || orgRepo == "" || role == "" {
		return false
	}

	githubAPIURL := fmt.Sprintf("https://api.github.com/repos/%s", orgRepo)
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
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
