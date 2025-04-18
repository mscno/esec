package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

var projectFormat = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

// validateOrgRepo ensures the orgRepo string is in the correct org/repo format
func validateOrgRepo(orgRepo string) error {
	if !projectFormat.MatchString(orgRepo) {
		return fmt.Errorf("invalid project name, must be org/repo")
	}
	return nil
}

func getUserInfo(token string) (string, int, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	var user struct {
		Login string `json:"login"`
		ID    int    `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", 0, err
	}
	return user.Login, user.ID, nil
}
