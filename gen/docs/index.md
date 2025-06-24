# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [esec/esec.proto](#esec_esec-proto)
    - [CheckInstallationRequest](#esec-CheckInstallationRequest)
    - [CheckInstallationResponse](#esec-CheckInstallationResponse)
    - [CreateOrganizationRequest](#esec-CreateOrganizationRequest)
    - [CreateOrganizationResponse](#esec-CreateOrganizationResponse)
    - [CreateProjectRequest](#esec-CreateProjectRequest)
    - [CreateProjectResponse](#esec-CreateProjectResponse)
    - [DeleteOrganizationRequest](#esec-DeleteOrganizationRequest)
    - [DeleteOrganizationResponse](#esec-DeleteOrganizationResponse)
    - [GetOrganizationRequest](#esec-GetOrganizationRequest)
    - [GetOrganizationResponse](#esec-GetOrganizationResponse)
    - [GetPerUserSecretsRequest](#esec-GetPerUserSecretsRequest)
    - [GetPerUserSecretsResponse](#esec-GetPerUserSecretsResponse)
    - [GetPerUserSecretsResponse.SecretsEntry](#esec-GetPerUserSecretsResponse-SecretsEntry)
    - [GetUserPublicKeyRequest](#esec-GetUserPublicKeyRequest)
    - [GetUserPublicKeyResponse](#esec-GetUserPublicKeyResponse)
    - [InitiateSessionRequest](#esec-InitiateSessionRequest)
    - [InitiateSessionResponse](#esec-InitiateSessionResponse)
    - [ListOrganizationsRequest](#esec-ListOrganizationsRequest)
    - [ListOrganizationsResponse](#esec-ListOrganizationsResponse)
    - [Organization](#esec-Organization)
    - [PerUserSecrets](#esec-PerUserSecrets)
    - [PerUserSecrets.SecretsEntry](#esec-PerUserSecrets-SecretsEntry)
    - [Project](#esec-Project)
    - [RegisterUserRequest](#esec-RegisterUserRequest)
    - [RegisterUserResponse](#esec-RegisterUserResponse)
    - [SecretMap](#esec-SecretMap)
    - [SecretMap.SecretsEntry](#esec-SecretMap-SecretsEntry)
    - [SetPerUserSecretsRequest](#esec-SetPerUserSecretsRequest)
    - [SetPerUserSecretsRequest.SecretsEntry](#esec-SetPerUserSecretsRequest-SecretsEntry)
    - [SetPerUserSecretsResponse](#esec-SetPerUserSecretsResponse)
    - [User](#esec-User)
  
    - [OrganizationType](#esec-OrganizationType)
  
    - [EsecService](#esec-EsecService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="esec_esec-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## esec/esec.proto



<a name="esec-CheckInstallationRequest"></a>

### CheckInstallationRequest
Request to check GitHub App installation


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| organization_name | [string](#string) |  |  |
| repository_name | [string](#string) |  | Format: &#34;owner/repo&#34; |






<a name="esec-CheckInstallationResponse"></a>

### CheckInstallationResponse
Response for checking GitHub App installation


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| installed | [bool](#bool) |  |  |
| installation_id | [string](#string) |  | The ID of the installation, if found |
| message | [string](#string) |  | Additional info, e.g., error message |






<a name="esec-CreateOrganizationRequest"></a>

### CreateOrganizationRequest
Request to create a new TEAM organization


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | The desired name for the team organization |






<a name="esec-CreateOrganizationResponse"></a>

### CreateOrganizationResponse
Response for creating an organization


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| organization | [Organization](#esec-Organization) |  | The newly created organization |






<a name="esec-CreateProjectRequest"></a>

### CreateProjectRequest
Request/response for creating a project


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| org_repo | [string](#string) |  |  |






<a name="esec-CreateProjectResponse"></a>

### CreateProjectResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [string](#string) |  |  |
| project | [string](#string) |  |  |






<a name="esec-DeleteOrganizationRequest"></a>

### DeleteOrganizationRequest
Request to delete an organization by ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | The ID of the organization to delete |






<a name="esec-DeleteOrganizationResponse"></a>

### DeleteOrganizationResponse
Response for deleting an organization


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [string](#string) |  | e.g., &#34;organization deleted&#34; |






<a name="esec-GetOrganizationRequest"></a>

### GetOrganizationRequest
Request to get a specific organization by ID


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | The ID of the organization to retrieve |






<a name="esec-GetOrganizationResponse"></a>

### GetOrganizationResponse
Response containing a single organization


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| organization | [Organization](#esec-Organization) |  |  |






<a name="esec-GetPerUserSecretsRequest"></a>

### GetPerUserSecretsRequest
Request/response for getting per-user secrets


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| org_repo | [string](#string) |  |  |






<a name="esec-GetPerUserSecretsResponse"></a>

### GetPerUserSecretsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| secrets | [GetPerUserSecretsResponse.SecretsEntry](#esec-GetPerUserSecretsResponse-SecretsEntry) | repeated |  |






<a name="esec-GetPerUserSecretsResponse-SecretsEntry"></a>

### GetPerUserSecretsResponse.SecretsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [SecretMap](#esec-SecretMap) |  |  |






<a name="esec-GetUserPublicKeyRequest"></a>

### GetUserPublicKeyRequest
Request/response for getting a user&#39;s public key


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| github_id | [string](#string) |  |  |






<a name="esec-GetUserPublicKeyResponse"></a>

### GetUserPublicKeyResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| github_id | [string](#string) |  |  |
| username | [string](#string) |  |  |
| public_key | [string](#string) |  |  |






<a name="esec-InitiateSessionRequest"></a>

### InitiateSessionRequest
Request to initiate a session


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| github_user_token | [string](#string) |  | The token obtained from GitHub device flow |






<a name="esec-InitiateSessionResponse"></a>

### InitiateSessionResponse
Response for initiating a session


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| session_token | [string](#string) |  | The app-managed session token |
| expires_at_unix | [int64](#int64) |  | Unix timestamp for session expiry |






<a name="esec-ListOrganizationsRequest"></a>

### ListOrganizationsRequest
Request to list organizations (potentially filtered in the future)

Future: Add filters like owner_id, type etc.






<a name="esec-ListOrganizationsResponse"></a>

### ListOrganizationsResponse
Response containing a list of organizations


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| organizations | [Organization](#esec-Organization) | repeated |  |






<a name="esec-Organization"></a>

### Organization
Represents an organization (personal or team)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | GitHub org ID, username (for personal), or generated UUID (for team) |
| name | [string](#string) |  | GitHub org/user login or team name |
| owner_github_id | [string](#string) |  | GitHub ID of the user who owns/created this record |
| type | [OrganizationType](#esec-OrganizationType) |  | Type of organization |
| created_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| updated_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |






<a name="esec-PerUserSecrets"></a>

### PerUserSecrets
Per-user secrets for a project


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| org_repo | [string](#string) |  |  |
| secrets | [PerUserSecrets.SecretsEntry](#esec-PerUserSecrets-SecretsEntry) | repeated | github_id -&gt; SecretMap |






<a name="esec-PerUserSecrets-SecretsEntry"></a>

### PerUserSecrets.SecretsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [SecretMap](#esec-SecretMap) |  |  |






<a name="esec-Project"></a>

### Project
Project information


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| org | [string](#string) |  |  |
| repo | [string](#string) |  |  |
| org_repo | [string](#string) |  | e.g., &#34;org/repo&#34; |
| created_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| updated_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |






<a name="esec-RegisterUserRequest"></a>

### RegisterUserRequest
Request/response for registering a user


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| public_key | [string](#string) |  |  |






<a name="esec-RegisterUserResponse"></a>

### RegisterUserResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [string](#string) |  |  |






<a name="esec-SecretMap"></a>

### SecretMap



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| secrets | [SecretMap.SecretsEntry](#esec-SecretMap-SecretsEntry) | repeated |  |






<a name="esec-SecretMap-SecretsEntry"></a>

### SecretMap.SecretsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="esec-SetPerUserSecretsRequest"></a>

### SetPerUserSecretsRequest
Request/response for setting per-user secrets


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| org_repo | [string](#string) |  |  |
| secrets | [SetPerUserSecretsRequest.SecretsEntry](#esec-SetPerUserSecretsRequest-SecretsEntry) | repeated |  |






<a name="esec-SetPerUserSecretsRequest-SecretsEntry"></a>

### SetPerUserSecretsRequest.SecretsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [SecretMap](#esec-SecretMap) |  |  |






<a name="esec-SetPerUserSecretsResponse"></a>

### SetPerUserSecretsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [string](#string) |  |  |






<a name="esec-User"></a>

### User
User information


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| github_id | [string](#string) |  |  |
| username | [string](#string) |  |  |
| public_key | [string](#string) |  |  |
| created_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| updated_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |





 


<a name="esec-OrganizationType"></a>

### OrganizationType
Enum defining the type of organization

| Name | Number | Description |
| ---- | ------ | ----------- |
| ORGANIZATION_TYPE_UNSPECIFIED | 0 |  |
| ORGANIZATION_TYPE_PERSONAL | 1 |  |
| ORGANIZATION_TYPE_TEAM | 2 |  |


 

 


<a name="esec-EsecService"></a>

### EsecService
ESEC main service

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateProject | [CreateProjectRequest](#esec-CreateProjectRequest) | [CreateProjectResponse](#esec-CreateProjectResponse) | Project management |
| RegisterUser | [RegisterUserRequest](#esec-RegisterUserRequest) | [RegisterUserResponse](#esec-RegisterUserResponse) | User registration |
| GetUserPublicKey | [GetUserPublicKeyRequest](#esec-GetUserPublicKeyRequest) | [GetUserPublicKeyResponse](#esec-GetUserPublicKeyResponse) | Public key retrieval |
| SetPerUserSecrets | [SetPerUserSecretsRequest](#esec-SetPerUserSecretsRequest) | [SetPerUserSecretsResponse](#esec-SetPerUserSecretsResponse) | Per-user secrets |
| GetPerUserSecrets | [GetPerUserSecretsRequest](#esec-GetPerUserSecretsRequest) | [GetPerUserSecretsResponse](#esec-GetPerUserSecretsResponse) |  |
| CreateOrganization | [CreateOrganizationRequest](#esec-CreateOrganizationRequest) | [CreateOrganizationResponse](#esec-CreateOrganizationResponse) | Creates a new team organization |
| ListOrganizations | [ListOrganizationsRequest](#esec-ListOrganizationsRequest) | [ListOrganizationsResponse](#esec-ListOrganizationsResponse) | Lists organizations (currently TEAM organizations) |
| GetOrganization | [GetOrganizationRequest](#esec-GetOrganizationRequest) | [GetOrganizationResponse](#esec-GetOrganizationResponse) | Gets a specific organization by ID |
| DeleteOrganization | [DeleteOrganizationRequest](#esec-DeleteOrganizationRequest) | [DeleteOrganizationResponse](#esec-DeleteOrganizationResponse) | Deletes a team organization by ID |
| InitiateSession | [InitiateSessionRequest](#esec-InitiateSessionRequest) | [InitiateSessionResponse](#esec-InitiateSessionResponse) | Initiates a new app-managed session using a GitHub user token |
| CheckInstallation | [CheckInstallationRequest](#esec-CheckInstallationRequest) | [CheckInstallationResponse](#esec-CheckInstallationResponse) | Checks if the GitHub App is installed on an org or repo |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

