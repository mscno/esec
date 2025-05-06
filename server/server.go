package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"
	esecpb "github.com/mscno/esec/gen/proto/go/esec"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
	"github.com/mscno/esec/server/middleware"
	model "github.com/mscno/esec/server/model"
	"google.golang.org/protobuf/types/known/timestamppb"
	// "github.com/google/uuid" // Removed UUID import
)

// --- Store Interface Definitions ---

// Errors related to User operations
var ErrUserExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")

// UserStore defines the interface for CRUD operations on Users.
type UserStore interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUser(ctx context.Context, githubID model.UserId) (*model.User, error)
	UpdateUser(ctx context.Context, githubID model.UserId, updateFn func(model.User) (model.User, error)) error
	DeleteUser(ctx context.Context, githubID model.UserId) error
	ListUsers(ctx context.Context) ([]model.User, error)
}

// Errors related to Project operations
var ErrProjectExists = errors.New("project already exists")
var ErrProjectNotFound = errors.New("project not found")

// ProjectStore defines the interface for CRUD operations on Projects and their secrets.
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

// Errors related to Organization operations
var ErrOrganizationNotFound = errors.New("organization not found")

// OrganizationStore defines the interface for CRUD operations on Organizations.
type OrganizationStore interface {
	CreateOrganization(ctx context.Context, org *model.Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*model.Organization, error)
	GetOrganizationByName(ctx context.Context, name string) (*model.Organization, error)
	UpdateOrganization(ctx context.Context, org *model.Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context) ([]*model.Organization, error)
}

// --- Server Implementation ---

// Server implements esecpbconnect.EsecServiceHandler
// It adapts the Handler logic for gRPC/protobuf
// Add dependencies as in Handler
type Server struct {
	Store             ProjectStore      // Use local interface type
	UserStore         UserStore         // Use local interface type
	OrganizationStore OrganizationStore // Use local interface type
	Logger            *slog.Logger
	userHasRoleInRepo UserHasRoleInRepoFunc
}

type UserHasRoleInRepoFunc func(token string, orgRepo model.OrgRepo, role string) bool

func NewServer(store ProjectStore, userStore UserStore, orgStore OrganizationStore, logger *slog.Logger, userHasRoleInRepo UserHasRoleInRepoFunc) *Server {
	srv := &Server{
		Store:             store,
		UserStore:         userStore,
		OrganizationStore: orgStore,
		Logger:            logger,
		userHasRoleInRepo: userHasRoleInRepo,
	}
	if userHasRoleInRepo == nil {
		userHasRoleInRepo = srv.defaultUserHasRoleInRepo
	}
	return srv
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

	// Attempt to upsert the user
	created := false
	existingUser, err := s.UserStore.GetUser(ctx, user.GitHubID) // Assign to existingUser
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) { // Use local error
			s.Logger.Error("failed to check existing user", "github_id", user.GitHubID, "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to check user existence: %w", err))
		}
		// User not found, create them
		if err := s.UserStore.CreateUser(ctx, user); err != nil {
			s.Logger.Error("failed to register user", "github_id", user.GitHubID, "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register user: %w", err))
		}
		created = true
	} else { // Use existingUser here
		// User found, update if public key differs
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

	// After user upsert, ensure personal organization exists
	personalOrgName := user.Username // Restore definition
	personalOrgID := user.Username   // Restore definition
	_, err = s.OrganizationStore.GetOrganizationByID(ctx, personalOrgID)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) { // Use local error
			s.Logger.Info("personal organization not found, creating...", "org_id", personalOrgID, "owner_github_id", user.GitHubID)
			personalOrg := &model.Organization{ // Restore definition
				ID:            personalOrgID,
				Name:          personalOrgName,
				OwnerGithubID: string(user.GitHubID),
				Type:          model.OrganizationTypePersonal,
			}
			if err := s.OrganizationStore.CreateOrganization(ctx, personalOrg); err != nil {
				// Log error but don't fail the user registration
				s.Logger.Error("failed to create personal organization", "org_id", personalOrgID, "error", err)
			} else {
				s.Logger.Info("created personal organization", "org_id", personalOrgID)
			}
		} else {
			// Log error fetching org but don't fail the user registration
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
	githubID := request.Msg.GetGithubId()
	if githubID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing github_id"))
	}
	user, err := s.UserStore.GetUser(ctx, model.UserId(githubID))
	if err != nil {
		if errors.Is(err, ErrUserNotFound) { // Use local error
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

	// TODO Wrap in TX
	err = s.Store.DeleteAllProjectUserSecrets(ctx, model.OrgRepo(orgRepo))
	if err != nil {
		s.Logger.Error("failed to delete all project user secrets", "orgRepo", orgRepo, "error", err)
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
	if len(secrets) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no secrets stored for this project, or you dont have the required permissions to access this project"))
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
func (s *Server) defaultUserHasRoleInRepo(token string, orgRepo model.OrgRepo, role string) bool {
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
	s.Logger.Debug("checking github api", "url", githubAPIURL, "token", token, "orgRepo", orgRepo, "role", role)
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

// CreateOrganization handles the creation of a new TEAM organization.
func (s *Server) CreateOrganization(ctx context.Context, req *connect.Request[esecpb.CreateOrganizationRequest]) (*connect.Response[esecpb.CreateOrganizationResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}

	orgName := req.Msg.GetName()
	if orgName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing organization name"))
	}
	// TODO: Add further validation for orgName (e.g., length, characters) if needed

	// Check if user is admin of the GitHub organization
	isAdmin, err := s.userIsGitHubOrgAdmin(ctx, ghuser.Token, orgName, ghuser.Login)
	if err != nil {
		s.Logger.Error("failed to check GitHub org admin status", "org", orgName, "user", ghuser.Login, "error", err)
		// Return a generic internal error to avoid leaking information about org existence/permissions
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify organization permissions"))
	}
	if !isAdmin {
		s.Logger.Warn("user is not admin of GitHub organization", "org", orgName, "user", ghuser.Login)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("user %s is not an admin of the GitHub organization %s", ghuser.Login, orgName))
	}

	// TODO: Check if the Esec GitHub App is installed on this organization.
	// This might require app authentication.

	// Use the provided name as the ID for the team org
	orgID := orgName
	ownerID := fmt.Sprintf("%d", ghuser.ID)

	newOrg := &model.Organization{
		ID:            orgID, // Use Name as ID
		Name:          orgName,
		OwnerGithubID: ownerID,
		Type:          model.OrganizationTypeTeam, // Explicitly set type to team
	}

	if err := s.OrganizationStore.CreateOrganization(ctx, newOrg); err != nil {
		// Check for specific errors like ID/name conflict
		if strings.Contains(err.Error(), "already exists") { // Basic check, might need refinement
			// Distinguish between ID and Name conflict if possible from store error
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("organization with ID or name '%s' already exists", orgName))
		}
		s.Logger.Error("failed to create organization", "name", orgName, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create organization: %w", err))
	}

	s.Logger.Info("created team organization", "org_id", orgID, "name", orgName, "owner_id", ownerID)

	pbOrg := modelToProtoOrg(newOrg)
	return connect.NewResponse(&esecpb.CreateOrganizationResponse{Organization: pbOrg}), nil
}

// userIsGitHubOrgAdmin checks if a user has the 'admin' role in a GitHub organization.
func (s *Server) userIsGitHubOrgAdmin(ctx context.Context, token, org, username string) (bool, error) {
	// Input validation
	if token == "" || org == "" || username == "" {
		return false, fmt.Errorf("token, org, and username cannot be empty")
	}

	// Construct the API URL safely
	apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/memberships/%s", url.PathEscape(org), url.PathEscape(username))

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create GitHub API request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28") // Best practice

	// Make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	// Handle common non-200 responses
	if resp.StatusCode == http.StatusNotFound {
		// Could be the org doesn't exist, or the user is not a member
		s.Logger.Info("GitHub org membership check returned 404", "org", org, "user", username, "url", apiURL)
		return false, nil // Not an admin if not found
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// Token invalid or lacks scope
		s.Logger.Warn("GitHub org membership check returned forbidden/unauthorized", "status", resp.StatusCode, "org", org, "user", username)
		return false, fmt.Errorf("github API access denied (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// Other unexpected error
		s.Logger.Error("GitHub org membership check returned unexpected status", "status", resp.StatusCode, "org", org, "user", username)
		// Consider reading the body for more details if needed, but be careful about leaking info
		return false, fmt.Errorf("github API returned unexpected status %d", resp.StatusCode)
	}

	// Decode the response
	var membership struct {
		State string `json:"state"` // "active", "pending"
		Role  string `json:"role"`  // "admin", "member"
	}
	if err := json.NewDecoder(resp.Body).Decode(&membership); err != nil {
		return false, fmt.Errorf("failed to decode GitHub membership response: %w", err)
	}

	// Check if the user is an active admin
	isAdmin := membership.State == "active" && membership.Role == "admin"
	s.Logger.Debug("GitHub org membership check result", "org", org, "user", username, "state", membership.State, "role", membership.Role, "is_admin", isAdmin)
	return isAdmin, nil
}

// ListOrganizations lists organizations accessible to the user (currently owned team orgs).
func (s *Server) ListOrganizations(ctx context.Context, req *connect.Request[esecpb.ListOrganizationsRequest]) (*connect.Response[esecpb.ListOrganizationsResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	ownerID := fmt.Sprintf("%d", ghuser.ID)

	allOrgs, err := s.OrganizationStore.ListOrganizations(ctx)
	if err != nil {
		s.Logger.Error("failed to list organizations", "owner_id", ownerID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list organizations: %w", err))
	}

	pbOrgs := make([]*esecpb.Organization, 0)
	for _, org := range allOrgs {
		// Filter: Only show orgs owned by the requesting user
		// TODO: Add logic later to show orgs the user is a member of
		if org.OwnerGithubID == ownerID {
			pbOrgs = append(pbOrgs, modelToProtoOrg(org))
		}
	}

	return connect.NewResponse(&esecpb.ListOrganizationsResponse{Organizations: pbOrgs}), nil
}

// GetOrganization retrieves a specific organization by ID, checking ownership.
func (s *Server) GetOrganization(ctx context.Context, req *connect.Request[esecpb.GetOrganizationRequest]) (*connect.Response[esecpb.GetOrganizationResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	ownerID := fmt.Sprintf("%d", ghuser.ID)
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

	// Permission Check: Only owner can get (for now)
	// TODO: Add member check later
	if org.OwnerGithubID != ownerID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to view organization"))
	}

	pbOrg := modelToProtoOrg(org)
	return connect.NewResponse(&esecpb.GetOrganizationResponse{Organization: pbOrg}), nil
}

// DeleteOrganization deletes a TEAM organization by ID, checking ownership.
func (s *Server) DeleteOrganization(ctx context.Context, req *connect.Request[esecpb.DeleteOrganizationRequest]) (*connect.Response[esecpb.DeleteOrganizationResponse], error) {
	ghuser, ok := ctx.Value("user").(middleware.GithubUser)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("user info missing from context"))
	}
	ownerID := fmt.Sprintf("%d", ghuser.ID)
	orgID := req.Msg.GetId()
	if orgID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("missing organization ID"))
	}

	// Fetch first to check ownership and type
	org, err := s.OrganizationStore.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			// Deleting non-existent is okay, return success
			return connect.NewResponse(&esecpb.DeleteOrganizationResponse{Status: "organization not found or already deleted"}), nil
		}
		s.Logger.Error("failed to get organization before delete", "org_id", orgID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get organization: %w", err))
	}

	// Permission Check: Only owner can delete
	if org.OwnerGithubID != ownerID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to delete organization"))
	}

	// Type Check: Cannot delete personal organizations
	if org.Type == model.OrganizationTypePersonal {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot delete personal organizations"))
	}

	if err := s.OrganizationStore.DeleteOrganization(ctx, orgID); err != nil {
		s.Logger.Error("failed to delete organization", "org_id", orgID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete organization: %w", err))
	}

	s.Logger.Info("deleted team organization", "org_id", orgID, "name", org.Name, "owner_id", ownerID)
	return connect.NewResponse(&esecpb.DeleteOrganizationResponse{Status: "organization deleted"}), nil
}

// modelToProtoOrg converts the internal model to the protobuf message.
func modelToProtoOrg(org *model.Organization) *esecpb.Organization {
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
