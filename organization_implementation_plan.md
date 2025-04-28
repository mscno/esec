# Implementation Plan: Team Organization Management

This plan outlines the steps to add features for managing Team Organizations in the `esec` application.

**Context:**

- Application Stack: Go, ConnectRPC, Protobuf, Kong (CLI).
- Existing Model: `server/model/organization.go` (`ID`, `Name`, `Type` [personal, team], GithubOwnerId, `CreatedAt`, `UpdatedAt`).
- Existing Datastore: `OrganizationStore` interface (`server/stores/organization_memory.go`) with memory implementation.
- Existing Server: `Server` struct in `server/server.go` implementing ConnectRPC handler.
- Existing Client: Go client library in `pkg/client/`.
- Existing CLI: `cliCtx`, command structure under `cli` and `CloudCmd` (`cmd/esec/commands/cli.go`), `setupConnectClient` helper.

**Implementation Steps:**

1. \*\* Add Google Datastore implementation of OrganizationDatastore in `server/stores/organization_datastore.go`
   Add unit tests for google datastore implementation.

2. **Implement Personal Organization Sync (`server/server.go`):**

   - **File:** `server/server.go`
   - **Changes:**
     - Locate the `RegisterUser` handler method.
     - After the existing user upsert logic (create or update), add a new block.
     - Call `s.OrganizationStore.GetOrganizationByID(ctx, user.Username)`.
     - If the returned error `errors.Is(err, stores.ErrOrganizationNotFound)`:
       - Create a `model.Organization` instance:
         - `ID`: `user.Username`
         - `Name`: `user.Username`
         - `OwnerGithubID`: `string(user.GitHubID)`
         - `Type`: `model.OrganizationTypePersonal`
       - Call `s.OrganizationStore.CreateOrganization(ctx, &personalOrg)`.
       - Log the outcome (success or error) of the organization creation using `s.Logger`.
     - If `GetOrganizationByID` returns a different error, log it.

3. **Update Protobuf Service Definition (`proto/esec/v1/esec.proto`):**

   - **File:** `proto/esec/v1/esec.proto`
   - **Changes:**
     - Define `CreateOrganizationRequest`, `CreateOrganizationResponse`, `ListOrganizationsRequest`, `ListOrganizationsResponse`, `GetOrganizationRequest`, `GetOrganizationResponse`, `DeleteOrganizationRequest`, `DeleteOrganizationResponse` messages as specified in requirements.
     - Add the corresponding RPC methods (`CreateOrganization`, `ListOrganizations`, `GetOrganization`, `DeleteOrganization`) to the `EsecService` definition.
     - Run `buf generate` in the terminal after saving the changes.

4. **Implement Server Handlers (`server/server.go`):**

   - **File:** `server/server.go`
   - **Changes:**
     - Implement the four new methods (`CreateOrganization`, `ListOrganizations`, `GetOrganization`, `DeleteOrganization`) on the `*Server` struct, matching the `EsecServiceHandler` interface.
     - **`CreateOrganization`:**
       - Get authenticated user (`ghuser`) from context.
       - Get `name` from `request.Msg`.
       - Validate `name` (e.g., non-empty).
       - Generate a unique `ID` (e.g., `github.com/google/uuid`).
       - Create `model.Organization` with `ID`, `Name`, `OwnerGithubID: string(ghuser.ID)`, `Type: model.OrganizationTypeTeam`.
       - Call `s.OrganizationStore.CreateOrganization`.
       - Handle potential errors (e.g., name conflict).
       - Convert the created `model.Organization` to `esecpb.Organization` (requires a helper function or manual mapping).
       - Return `connect.NewResponse(&esecpb.CreateOrganizationResponse{Organization: &pbOrg})`.
     - **`ListOrganizations`:**
       - Get authenticated user (`ghuser`) from context.
       - Call `s.OrganizationStore.ListOrganizations`.
       - Iterate through the results:
         - Filter: Keep only organizations where `org.OwnerGithubID == string(ghuser.ID)`.
         - Convert kept `model.Organization` to `esecpb.Organization`.
       - Return `connect.NewResponse(&esecpb.ListOrganizationsResponse{Organizations: pbOrgs})`.
     - **`GetOrganization`:**
       - Get authenticated user (`ghuser`) from context.
       - Get `id` from `request.Msg`.
       - Call `s.OrganizationStore.GetOrganizationByID`.
       - Handle `ErrOrganizationNotFound` -> `connect.CodeNotFound`.
       - Check permission: If `retrievedOrg.OwnerGithubID != string(ghuser.ID)`, return `connect.CodePermissionDenied`.
       - Convert `model.Organization` to `esecpb.Organization`.
       - Return `connect.NewResponse(&esecpb.GetOrganizationResponse{Organization: &pbOrg})`.
     - **`DeleteOrganization`:**
       - Get authenticated user (`ghuser`) from context.
       - Get `id` from `request.Msg`.
       - Call `s.OrganizationStore.GetOrganizationByID` to fetch the org first.
       - Handle `ErrOrganizationNotFound` -> `connect.CodeNotFound`.
       - Check permission: If `retrievedOrg.OwnerGithubID != string(ghuser.ID)`, return `connect.CodePermissionDenied`.
       - Check type: If `retrievedOrg.Type == model.OrganizationTypePersonal`, return `connect.CodeInvalidArgument` (cannot delete personal orgs).
       - Call `s.OrganizationStore.DeleteOrganization(ctx, id)`.
       - Handle potential errors during deletion.
       - Return `connect.NewResponse(&esecpb.DeleteOrganizationResponse{Status: \"organization deleted\"})`.
     - **Helper Function:** Create a helper `func modelToProtoOrg(org *model.Organization) *esecpb.Organization` (or similar) for conversions.

5. **Implement Client Methods (`pkg/client/`):**

   - **Files:** `pkg/client/client.go`, `pkg/client/client_connect.go`
   - **Changes:**
     - **`client.go`:** Add `CreateOrganization`, `ListOrganizations`, `GetOrganization`, `DeleteOrganization` method signatures to the `Client` interface.
     - **`client_connect.go`:** Implement the new interface methods on `*ConnectClient` by calling the corresponding generated gRPC client methods (e.g., `c.grpcClient.CreateOrganization(ctx, connect.NewRequest(req))`). Handle request/response conversion if needed.

6. **Implement CLI Commands (`cmd/esec/commands/`):**
   - **Files:** `cmd/esec/commands/cli.go`, `cmd/esec/commands/orgs.go` (new)
   - **Changes:**
     - **`cli.go`:** Add `Orgs OrgsCmd \`cmd:\"\" help:\"Manage team organizations\"\``field to the`CloudCmd` struct.
     - **`orgs.go` (New File):**
       - Define `OrgsCmd` struct.
       - Define `OrgsCreateCmd` struct with `Name string \`arg:\"\" required:\"\" help:\"Name for the new team organization.\"\``.
       - Define `OrgsListCmd` struct (no fields needed initially).
       - Define `OrgsDeleteCmd` struct with `ID string \`arg:\"\" required:\"\" help:\"ID of the team organization to delete.\"\``.
       - Implement `Run(ctx *cliCtx, parent *CloudCmd) error` for each subcommand struct:
         - Call `setupConnectClient(ctx, parent)` to get the `client.Client`.
         - Call the corresponding client method (e.g., `client.CreateOrganization(ctx, c.Name)`).
         - Handle errors.
         - Print results clearly (e.g., using `fmt.Printf` or table writer for list).
