package model

import "time"

// OrganizationType differentiates between personal (implicit) and team organizations.
type OrganizationType string

const (
	OrganizationTypePersonal OrganizationType = "personal"
	OrganizationTypeTeam     OrganizationType = "team"
)

// Organization represents a GitHub organization or potentially a user acting as an organization.
type Organization struct {
	ID            string           `json:"id" boltholdKey:""` // GitHub org ID, username (for personal), or generated UUID (for team)
	Name          string           `json:"name" boltholdIndex:"Name"` // GitHub org/user login or team name
	OwnerGithubID string           `json:"owner_github_id" boltholdIndex:"OwnerGithubID"` // GitHub ID of the user who owns/created this record
	Type          OrganizationType `json:"type" boltholdIndex:"Type"`          // Type of organization (personal or team)
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	// Add other relevant fields like Members, Projects list if needed later
}
