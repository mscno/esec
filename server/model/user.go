package model

type UserId string
type User struct {
	GitHubID  UserId `json:"github_id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

func (u UserId) String() string {
	return string(u)
}
