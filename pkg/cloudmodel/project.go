package cloudmodel

type PrivateKeyName string

func (o PrivateKeyName) String() string {
	return string(o)
}

type OrgRepo string

func (o OrgRepo) String() string {
	return string(o)
}

type Project struct {
	OrgRepo OrgRepo
}

// SecretPair represents a key-value pair for a secret
type SecretPair struct {
	Key   PrivateKeyName `datastore:"key"`
	Value string         `datastore:"value,noindex"`
}

// ProjectUserSecrets represents secrets for a specific user in a project
type ProjectUserSecrets struct {
	ProjectID OrgRepo      `datastore:"project_id"` // OrgRepo
	UserId    UserId       `datastore:"user_id"`
	Secrets   []SecretPair `datastore:"secrets,noindex"`
}
