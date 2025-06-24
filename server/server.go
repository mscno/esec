package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/go-github/v71/github"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
	pkgSession "github.com/mscno/esec/pkg/session" // Alias to avoid conflict
	"github.com/mscno/esec/server/middleware"
	model "github.com/mscno/esec/server/model"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Store Interface Definitions ---
// ... (Store interfaces remain the same) ...
var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")

type UserStore interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUser(ctx context.Context, githubID model.UserId) (*model.User, error)
	UpdateUser(ctx context.Context, githubID model.UserId, updateFn func(model.User) (model.User, error)) error
	DeleteUser(ctx context.Context, githubID model.UserId) error
	ListUsers(ctx context.Context) ([]model.User, error)
}

var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")

type ProjectStore interface {
	CreateProject(ctx context.Context, project model.Project) error
	GetProject(ctx context.Context, orgRepo model.OrgRepo) (model.Project, error)
	UpdateProject(ctx context.Context, orgRepo model.OrgRepo, updateFn func(project model.Project) (model.Project, error)) error
	ListProjects(ctx context.Context) ([]model.Project, error)
	DeleteProject(ctx context.Context, orgRepo model.OrgRepo) error
	SetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userId model.UserId, secrets map[model.PrivateKeyName]string) error
	GetProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userId model.UserId) (map[model.PrivateKeyName]string, error)
	GetAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) (map[model.UserId]map[model.PrivateKeyName]string, error)
	DeleteProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo, userID model.UserId) error
	DeleteAllProjectUserSecrets(ctx context.Context, orgRepo model.OrgRepo) error
}

var ErrOrganizationNotFound = errors.New("organization not found")

type OrganizationStore interface {
	CreateOrganization(ctx context.Context, org *model.Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*model.Organization, error)
	GetOrganizationByName(ctx context.Context, name string) (*model.Organization, error)
	UpdateOrganization(ctx context.Context, org *model.Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context) ([]*model.Organization, error)
}

// --- Server Implementation ---
type Server struct {
	Store             ProjectStore
	UserStore         UserStore
	OrganizationStore OrganizationStore
	Logger            *slog.Logger
	githubAppClient   *github.Client // For GitHub App authenticated calls
	// userHasRoleInRepo UserHasRoleInRepoFunc // This will be replaced by internal logic using githubAppClient
}

// UserHasRoleInRepoFunc is now an internal detail or a helper method.
// type UserHasRoleInRepoFunc func(token string, orgRepo model.OrgRepo, role string) bool

func NewServer(store ProjectStore, userStore UserStore, orgStore OrganizationStore, logger *slog.Logger, ghAppClient *github.Client) *Server {
	srv := &Server{
		Store:             store,
		UserStore:         userStore,
		OrganizationStore: orgStore,
		Logger:            logger,
		githubAppClient:   ghAppClient,
	}
	return srv
}

var _ esecpbconnect.EsecServiceHandler = (*Server)(nil)

// Helper to get authenticated user from context
func getAuthenticatedUser(ctx context.Context) (middleware.AppSessionUser, error) {
	user, ok := ctx.Value("user").(middleware.AppSessionUser)
	if !ok {
		return middleware.AppSessionUser{}, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("authentication required: user info missing from context or not AppSessionUser type"))
	}
	return user, nil
}

func (s *Server) InitiateSession(ctx context.Context, request *connect.Request[esecpb.InitiateSessionRequest]) (*connect.Response[esecpb.InitiateSessionResponse], error) {
	githubUserToken := request.Msg.GetGithubUserToken()
	if githubUserToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("GitHub user token is required"))
	}

	// Validate the GitHub user token (this logic was in middleware.ValidateGitHubToken)
	ghLogin, ghID, err := middleware.GetUserInfo(githubUserToken) // Using the renamed GetUserInfo
	if err != nil {
		s.Logger.Warn("Failed to validate GitHub user token during session initiation", "error", err)
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid GitHub user token: %w", err))
	}
	if ghLogin == "" || ghID == 0 {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("could not retrieve valid user info from GitHub token"))
	}

	// Generate app session token
	sessionToken, expiresAt, err := pkgSession.GenerateToken(strconv.Itoa(ghID), ghLogin)
	if err != nil {
		s.Logger.Error("Failed to generate session token", "error", err, "github_login", ghLogin)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create session"))
	}

	s.Logger.Info("Session initiated successfully", "github_login", ghLogin, "github_id", ghID)
	return connect.NewResponse(&esecpb.InitiateSessionResponse{
		SessionToken:  sessionToken,
		ExpiresAtUnix: expiresAt,
	}), nil
}

func (s *Server) CreateProject(ctx context.Context, request *connect.Request[esecpb.CreateProjectRequest]) (*connect.Response[esecpb.CreateProjectResponse], error) {
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err // err is already a connect.Error
	}

	orgRepo := request.Msg.GetOrgRepo()
	if orgRepo == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepo); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}

	// Permission check using GitHub App client
	hasAccess, checkErr := s.userHasRoleInRepo(ctx, model.OrgRepo(orgRepo), "admin", appUser.GithubLogin)
	if checkErr != nil {
		s.Logger.Error("Error checking repository role", "orgRepo", orgRepo, "user", appUser.GithubLogin, "error", checkErr)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("failed to verify repository permissions for %s on %s", appUser.GithubLogin, orgRepo))
	}
	if !hasAccess {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("user %s does not have admin role in %s", appUser.GithubLogin, orgRepo))
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
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

	user := model.User{
		GitHubID:  model.UserId(appUser.GithubUserID), // Use ID from session
		Username:  appUser.GithubLogin,                // Use Login from session
		PublicKey: request.Msg.GetPublicKey(),
	}
	if user.GitHubID == "" || user.Username == "" || user.PublicKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing user fields"))
	}

	created := false
	existingUser, err := s.UserStore.GetUser(ctx, user.GitHubID)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			s.Logger.Error("failed to check existing user", "github_id", user.GitHubID, "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to check user existence: %w", err))
		}
		if err := s.UserStore.CreateUser(ctx, user); err != nil {
			s.Logger.Error("failed to register user", "github_id", user.GitHubID, "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register user: %w", err))
		}
		created = true
	} else {
		if existingUser.PublicKey != user.PublicKey {
			s.Logger.Info("updating user public key", "github_id", user.GitHubID)
			err = s.UserStore.UpdateUser(ctx, user.GitHubID, func(u model.User) (model.User, error) {
				u.PublicKey = user.PublicKey
				return u, nil
			})
			if err != nil {
				s.Logger.Error("failed to update user public key", "github_id", user.GitHubID, "error", err)
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user public key: %w", err))
			}
		}
	}

	personalOrgName := user.Username
	personalOrgID := user.Username // For personal orgs, ID is often the username
	_, err = s.OrganizationStore.GetOrganizationByID(ctx, personalOrgID)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			s.Logger.Info("personal organization not found, creating...", "org_id", personalOrgID, "owner_github_id", user.GitHubID)
			personalOrg := &model.Organization{
				ID:            personalOrgID,
				Name:          personalOrgName,
				OwnerGithubID: string(user.GitHubID),
				Type:          model.OrganizationTypePersonal,
			}
			if err := s.OrganizationStore.CreateOrganization(ctx, personalOrg); err != nil {
				s.Logger.Error("failed to create personal organization", "org_id", personalOrgID, "error", err)
			} else {
				s.Logger.Info("created personal organization", "org_id", personalOrgID)
			}
		} else {
			s.Logger.Error("failed to check for personal organization", "org_id", personalOrgID, "error", err)
		}
	}

	status := "user updated"
	if created {
		status = "user registered"
	}
	return connect.NewResponse(&esecpb.RegisterUserResponse{
		Status: status,
	}), nil
}

func (s *Server) GetUserPublicKey(ctx context.Context, request *connect.Request[esecpb.GetUserPublicKeyRequest]) (*connect.Response[esecpb.GetUserPublicKeyResponse], error) {
	// This endpoint might be called by users to get other users' keys.
	// The calling user must be authenticated via app session.
	_, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

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
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

	orgRepoStr := request.Msg.GetOrgRepo()
	if orgRepoStr == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepoStr); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}
	orgRepo := model.OrgRepo(orgRepoStr)

	_, err = s.Store.GetProject(ctx, orgRepo)
	if err != nil {
		s.Logger.Error("project not found", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project not found: %w", err))
	}

	// Permission check
	hasAccess, checkErr := s.userHasRoleInRepo(ctx, orgRepo, "admin", appUser.GithubLogin)
	if checkErr != nil {
		s.Logger.Error("Error checking repository role for SetPerUserSecrets", "orgRepo", orgRepo, "user", appUser.GithubLogin, "error", checkErr)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("failed to verify repository permissions"))
	}
	if !hasAccess {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("user %s is not admin of project %s", appUser.GithubLogin, orgRepo))
	}

	secrets := make(map[model.UserId]map[model.PrivateKeyName]string)
	for userIdStr, secretMapProto := range request.Msg.GetSecrets() {
		userIdTyped := model.UserId(userIdStr)
		secrets[userIdTyped] = make(map[model.PrivateKeyName]string)
		for key, ciphertext := range secretMapProto.GetSecrets() {
			keyTyped := model.PrivateKeyName(key)
			secrets[userIdTyped][keyTyped] = ciphertext
		}
	}

	// TODO Wrap in TX if store supports it
	err = s.Store.DeleteAllProjectUserSecrets(ctx, orgRepo)
	if err != nil {
		s.Logger.Error("failed to delete all project user secrets", "orgRepo", orgRepo, "error", err)
		// Continue, as SetProjectUserSecrets will overwrite or create
	}

	for userId, userSecrets := range secrets {
		err := s.Store.SetProjectUserSecrets(ctx, orgRepo, userId, userSecrets)
		if err != nil {
			s.Logger.Error("failed to set project user secrets for user", "orgRepo", orgRepo, "userID", userId, "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to set project user secrets for %s: %w", userId, err))
		}
	}

	return connect.NewResponse(&esecpb.SetPerUserSecretsResponse{Status: "ok"}), nil
}

func (s *Server) GetPerUserSecrets(ctx context.Context, request *connect.Request[esecpb.GetPerUserSecretsRequest]) (*connect.Response[esecpb.GetPerUserSecretsResponse], error) {
	appUser, err := getAuthenticatedUser(ctx) // Ensure caller is authenticated
	if err != nil {
		return nil, err
	}

	orgRepoStr := request.Msg.GetOrgRepo()
	if orgRepoStr == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing org_repo"))
	}
	if err := validateOrgRepo(orgRepoStr); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid org_repo: %w", err))
	}
	orgRepo := model.OrgRepo(orgRepoStr)

	_, err = s.Store.GetProject(ctx, orgRepo)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("project not found: %w", err))
	}

	// Permission check: User needs at least read access to the repo to pull secrets for themselves.
	// The current implementation of PullKeysPerUser in CLI implies user pulls their own secrets.
	// If this method is to allow admins to pull all, permission model needs refinement.
	// For now, assume user is pulling for themselves, so they need to be part of the project.
	// A simple check: are there any secrets for this user in this project?
	// A more robust check would be `userHasRoleInRepo(ctx, orgRepo, "read", appUser.GithubLogin)`
	// Let's assume the secrets store handles filtering by user for now.

	secrets, err := s.Store.GetAllProjectUserSecrets(ctx, orgRepo)
	if err != nil {
		s.Logger.Error("failed to get all project user secrets", "orgRepo", orgRepo, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get per-user secrets: %w", err))
	}

	// Filter secrets: only return secrets for the currently authenticated user (appUser)
	// unless the user is an admin of the project (then return all).
	// This logic is for the server to decide what to return based on caller's permissions.
	userIsAdmin, _ := s.userHasRoleInRepo(ctx, orgRepo, "admin", appUser.GithubLogin)

	respSecrets := make(map[string]*esecpb.SecretMap)
	if userIsAdmin {
		for userID, secretMap := range secrets {
			pbSecretMap := &esecpb.SecretMap{Secrets: make(map[string]string)}
			for key, cipher := range secretMap {
				pbSecretMap.Secrets[string(key)] = cipher
			}
			respSecrets[string(userID)] = pbSecretMap
		}
	} else {
		// Regular user: only return their own secrets
		if userSecrets, ok := secrets[model.UserId(appUser.GithubUserID)]; ok {
			pbSecretMap := &esecpb.SecretMap{Secrets: make(map[string]string)}
			for key, cipher := range userSecrets {
				pbSecretMap.Secrets[string(key)] = cipher
			}
			respSecrets[appUser.GithubUserID] = pbSecretMap
		} else {
			// No secrets for this user, or user not part of project sharing
			s.Logger.Info("No secrets found for user in project or user lacks permissions", "user", appUser.GithubLogin, "project", orgRepo)
			// Return empty map, not an error, if user is valid but has no secrets shared.
			// If they shouldn't even know the project exists, GetProject would have failed earlier.
		}
	}

	if len(respSecrets) == 0 {
		s.Logger.Info("No secrets to return for user or project", "user", appUser.GithubLogin, "project", orgRepo)
		// It's not an error to have no secrets.
	}

	return connect.NewResponse(&esecpb.GetPerUserSecretsResponse{Secrets: respSecrets}), nil
}

// userHasRoleInRepo checks if the given GitHub user login has a specific role in the org/repo.
// Uses the server's GitHub App client.
func (s *Server) userHasRoleInRepo(ctx context.Context, orgRepo model.OrgRepo, role string, userLogin string) (bool, error) {
	if s.githubAppClient == nil {
		s.Logger.Error("GitHub App client is not initialized. Cannot check repository role.")
		return false, errors.New("github app client not available")
	}
	if userLogin == "" || orgRepo == "" || role == "" {
		return false, errors.New("userLogin, orgRepo, and role cannot be empty")
	}

	parts := strings.Split(string(orgRepo), "/")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid orgRepo format: %s", orgRepo)
	}
	orgName := parts[0]
	repoName := parts[1]

	// GitHub API to get repository permissions for a user
	// GET /repos/{owner}/{repo}/collaborators/{username}/permission
	permission, resp, err := s.githubAppClient.Repositories.GetPermissionLevel(ctx, orgName, repoName, userLogin)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden) {
			s.Logger.Warn("User not a collaborator or repo not found/accessible by app", "org", orgName, "repo", repoName, "user", userLogin, "status", resp.StatusCode)
			return false, nil // Not an error, just no permission or not found
		}
		s.Logger.Error("Error getting repository permission level from GitHub", "org", orgName, "repo", repoName, "user", userLogin, "error", err)
		return false, fmt.Errorf("failed to get permission level for %s on %s/%s: %w", userLogin, orgName, repoName, err)
	}

	s.Logger.Debug("GitHub permission level check", "user", userLogin, "repo", orgRepo, "permission", permission.GetPermission(), "role_required", role)

	// Map GitHub's permission strings ("admin", "write", "read", "none") to our roles
	// This might need adjustment based on how specific your roles are.
	// For "admin" role:
	if role == "admin" {
		return permission.GetPermission() == "admin", nil
	}
	// For "write" role:
	if role == "write" {
		return permission.GetPermission() == "admin" || permission.GetPermission() == "write", nil
	}
	// For "read" role:
	if role == "read" {
		p := permission.GetPermission()
		return p == "admin" || p == "write" || p == "read", nil
	}

	return false, fmt.Errorf("unknown role: %s", role)
}

// CreateOrganization handles the creation of a new TEAM organization.
func (s *Server) CreateOrganization(ctx context.Context, req *connect.Request[esecpb.CreateOrganizationRequest]) (*connect.Response[esecpb.CreateOrganizationResponse], error) {
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

	orgName := req.Msg.GetName()
	if orgName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing organization name"))
	}

	isAdmin, checkErr := s.userIsGitHubOrgAdmin(ctx, orgName, appUser.GithubLogin)
	if checkErr != nil {
		s.Logger.Error("failed to check GitHub org admin status", "org", orgName, "user", appUser.GithubLogin, "error", checkErr)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify organization permissions"))
	}
	if !isAdmin {
		s.Logger.Warn("user is not admin of GitHub organization", "org", orgName, "user", appUser.GithubLogin)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("user %s is not an admin of the GitHub organization %s", appUser.GithubLogin, orgName))
	}

	// Check if the esec GitHub App is installed on this organization.
	installed, _, checkErr := s.isAppInstalledOnOrg(ctx, orgName)
	if checkErr != nil {
		s.Logger.Error("Failed to check GitHub App installation status for organization", "org", orgName, "error", checkErr)
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("could not verify app installation status for organization %s", orgName))
	}
	if !installed {
		s.Logger.Warn("esec GitHub App is not installed on organization", "org", orgName)
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("esec GitHub App must be installed on organization %s to create a team", orgName))
	}

	orgID := orgName // Use GitHub org name as the ID for team orgs
	ownerID := appUser.GithubUserID

	newOrg := &model.Organization{
		ID:            orgID,
		Name:          orgName,
		OwnerGithubID: ownerID,
		Type:          model.OrganizationTypeTeam,
	}

	if err := s.OrganizationStore.CreateOrganization(ctx, newOrg); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("organization with ID or name '%s' already exists", orgName))
		}
		s.Logger.Error("failed to create organization", "name", orgName, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create organization: %w", err))
	}

	s.Logger.Info("created team organization", "org_id", orgID, "name", orgName, "owner_id", ownerID)
	pbOrg := modelToProtoOrg(newOrg)
	return connect.NewResponse(&esecpb.CreateOrganizationResponse{Organization: pbOrg}), nil
}

// userIsGitHubOrgAdmin checks if a user has the 'admin' role in a GitHub organization using the app client.
func (s *Server) userIsGitHubOrgAdmin(ctx context.Context, orgName string, userLogin string) (bool, error) {
	if s.githubAppClient == nil {
		s.Logger.Error("GitHub App client is not initialized. Cannot check org admin status.")
		return false, errors.New("github app client not available")
	}
	if orgName == "" || userLogin == "" {
		return false, errors.New("orgName and userLogin cannot be empty")
	}

	membership, resp, err := s.githubAppClient.Organizations.GetOrgMembership(ctx, userLogin, orgName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			s.Logger.Info("User not a member of org, or org not found/accessible by app", "org", orgName, "user", userLogin)
			return false, nil // Not an admin if not a member or org not found
		}
		s.Logger.Error("Error getting organization membership from GitHub", "org", orgName, "user", userLogin, "error", err)
		return false, fmt.Errorf("failed to get org membership for %s in %s: %w", userLogin, orgName, err)
	}

	isAdmin := membership.GetState() == "active" && membership.GetRole() == "admin"
	s.Logger.Debug("GitHub org membership check result", "org", orgName, "user", userLogin, "state", membership.GetState(), "role", membership.GetRole(), "is_admin", isAdmin)
	return isAdmin, nil
}

// ListOrganizations, GetOrganization, DeleteOrganization need to use appUser from getAuthenticatedUser
// ... (Implementations for List, Get, Delete Organization similar to above, using appUser) ...
func (s *Server) ListOrganizations(ctx context.Context, req *connect.Request[esecpb.ListOrganizationsRequest]) (*connect.Response[esecpb.ListOrganizationsResponse], error) {
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	ownerID := appUser.GithubUserID

	allOrgs, err := s.OrganizationStore.ListOrganizations(ctx)
	if err != nil {
		s.Logger.Error("failed to list organizations", "owner_id", ownerID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list organizations: %w", err))
	}

	pbOrgs := make([]*esecpb.Organization, 0)
	for _, org := range allOrgs {
		if org.OwnerGithubID == ownerID || org.Type == model.OrganizationTypePersonal && org.ID == appUser.GithubLogin { // Personal orgs are identified by login
			pbOrgs = append(pbOrgs, modelToProtoOrg(org))
		}
		// TODO: Add logic to list team orgs where the user is a member (not just owner)
		// This would require checking GitHub team memberships via the app.
	}

	return connect.NewResponse(&esecpb.ListOrganizationsResponse{Organizations: pbOrgs}), nil
}

func (s *Server) GetOrganization(ctx context.Context, req *connect.Request[esecpb.GetOrganizationRequest]) (*connect.Response[esecpb.GetOrganizationResponse], error) {
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

	orgID := req.Msg.GetId()
	if orgID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing organization ID"))
	}

	org, err := s.OrganizationStore.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("organization not found"))
		}
		s.Logger.Error("failed to get organization", "org_id", orgID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get organization: %w", err))
	}

	// Permission Check: Owner or member (for team orgs).
	// Personal orgs are identified by login matching ID.
	canAccess := false
	if org.Type == model.OrganizationTypePersonal && org.ID == appUser.GithubLogin {
		canAccess = true
	} else if org.Type == model.OrganizationTypeTeam {
		if org.OwnerGithubID == appUser.GithubUserID {
			canAccess = true
		} else {
			// TODO: Check if appUser is a member of the GitHub org `org.Name`
			// isMember, _ := s.userIsGitHubOrgMember(ctx, org.Name, appUser.GithubLogin)
			// if isMember { canAccess = true }
			s.Logger.Warn("Membership check for team org not yet implemented for GetOrganization", "org", org.Name, "user", appUser.GithubLogin)
		}
	}

	if !canAccess {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to view organization %s", orgID))
	}

	pbOrg := modelToProtoOrg(org)
	return connect.NewResponse(&esecpb.GetOrganizationResponse{Organization: pbOrg}), nil
}

func (s *Server) DeleteOrganization(ctx context.Context, req *connect.Request[esecpb.DeleteOrganizationRequest]) (*connect.Response[esecpb.DeleteOrganizationResponse], error) {
	appUser, err := getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}
	ownerID := appUser.GithubUserID
	orgID := req.Msg.GetId()
	if orgID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing organization ID"))
	}

	org, err := s.OrganizationStore.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			return connect.NewResponse(&esecpb.DeleteOrganizationResponse{Status: "organization not found or already deleted"}), nil
		}
		s.Logger.Error("failed to get organization before delete", "org_id", orgID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get organization: %w", err))
	}

	if org.Type == model.OrganizationTypePersonal {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot delete personal organizations"))
	}

	// Only owner of the esec team record can delete it.
	if org.OwnerGithubID != ownerID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied: only the creator of the team record can delete it"))
	}

	if err := s.OrganizationStore.DeleteOrganization(ctx, orgID); err != nil {
		s.Logger.Error("failed to delete organization", "org_id", orgID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete organization: %w", err))
	}

	s.Logger.Info("deleted team organization", "org_id", orgID, "name", org.Name, "deleter_id", ownerID)
	return connect.NewResponse(&esecpb.DeleteOrganizationResponse{Status: "organization deleted"}), nil
}

func modelToProtoOrg(org *model.Organization) *esecpb.Organization {
	// ... (modelToProtoOrg remains the same) ...
	if org == nil {
		return nil
	}
	pbType := esecpb.OrganizationType_ORGANIZATION_TYPE_UNSPECIFIED
	switch org.Type {
	case model.OrganizationTypePersonal:
		pbType = esecpb.OrganizationType_ORGANIZATION_TYPE_PERSONAL
	case model.OrganizationTypeTeam:
		pbType = esecpb.OrganizationType_ORGANIZATION_TYPE_TEAM
	}

	return &esecpb.Organization{
		Id:            org.ID,
		Name:          org.Name,
		OwnerGithubId: org.OwnerGithubID,
		Type:          pbType,
		CreatedAt:     timestamppb.New(org.CreatedAt),
		UpdatedAt:     timestamppb.New(org.UpdatedAt),
	}
}

// --- GitHub App Installation Check ---

func (s *Server) isAppInstalledOnOrg(ctx context.Context, orgName string) (bool, string, error) {
	if s.githubAppClient == nil {
		return false, "", errors.New("github app client not configured")
	}
	installation, resp, err := s.githubAppClient.Apps.FindOrganizationInstallation(ctx, orgName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, "", nil // Not installed
		}
		return false, "", fmt.Errorf("failed to get org installation: %w", err)
	}
	return true, strconv.FormatInt(installation.GetID(), 10), nil
}

func (s *Server) isAppInstalledOnRepo(ctx context.Context, owner, repo string) (bool, string, error) {
	if s.githubAppClient == nil {
		return false, "", errors.New("github app client not configured")
	}
	installation, resp, err := s.githubAppClient.Apps.FindRepositoryInstallation(ctx, owner, repo)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, "", nil // Not installed
		}
		return false, "", fmt.Errorf("failed to get repo installation: %w", err)
	}
	return true, strconv.FormatInt(installation.GetID(), 10), nil
}

func (s *Server) CheckInstallation(ctx context.Context, request *connect.Request[esecpb.CheckInstallationRequest]) (*connect.Response[esecpb.CheckInstallationResponse], error) {
	_, err := getAuthenticatedUser(ctx) // Ensure caller is authenticated
	if err != nil {
		return nil, err
	}

	if s.githubAppClient == nil {
		s.Logger.Error("GitHub App client is not configured, cannot check installation status.")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("server GitHub App not configured"))
	}

	var installed bool
	var installationID string
	var checkErr error
	var msg string

	if orgName := request.Msg.GetOrganizationName(); orgName != "" {
		installed, installationID, checkErr = s.isAppInstalledOnOrg(ctx, orgName)
		if checkErr != nil {
			msg = fmt.Sprintf("Error checking installation for organization %s: %v", orgName, checkErr)
			s.Logger.Warn(msg)
		} else if installed {
			msg = fmt.Sprintf("App is installed on organization %s (ID: %s)", orgName, installationID)
		} else {
			msg = fmt.Sprintf("App is not installed on organization %s", orgName)
		}
	} else if repoNameFull := request.Msg.GetRepositoryName(); repoNameFull != "" {
		parts := strings.Split(repoNameFull, "/")
		if len(parts) != 2 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("repository_name must be in 'owner/repo' format"))
		}
		owner, repo := parts[0], parts[1]
		installed, installationID, checkErr = s.isAppInstalledOnRepo(ctx, owner, repo)
		if checkErr != nil {
			msg = fmt.Sprintf("Error checking installation for repository %s: %v", repoNameFull, checkErr)
			s.Logger.Warn(msg)
		} else if installed {
			msg = fmt.Sprintf("App is installed on repository %s (ID: %s)", repoNameFull, installationID)
		} else {
			msg = fmt.Sprintf("App is not installed on repository %s", repoNameFull)
		}
	} else {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("either organization_name or repository_name must be provided"))
	}

	return connect.NewResponse(&esecpb.CheckInstallationResponse{
		Installed:      installed && checkErr == nil, // Only true if no error and installed
		InstallationId: installationID,
		Message:        msg,
	}), nil
}
