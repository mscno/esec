# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [esec/esec.proto](#esec_esec-proto)
    - [CreateProjectRequest](#esec-CreateProjectRequest)
    - [CreateProjectResponse](#esec-CreateProjectResponse)
    - [GetPerUserSecretsRequest](#esec-GetPerUserSecretsRequest)
    - [GetPerUserSecretsResponse](#esec-GetPerUserSecretsResponse)
    - [GetPerUserSecretsResponse.SecretsEntry](#esec-GetPerUserSecretsResponse-SecretsEntry)
    - [GetUserPublicKeyRequest](#esec-GetUserPublicKeyRequest)
    - [GetUserPublicKeyResponse](#esec-GetUserPublicKeyResponse)
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
  
    - [EsecService](#esec-EsecService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="esec_esec-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## esec/esec.proto



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

