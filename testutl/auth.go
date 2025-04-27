package testutl

import (
	"github.com/mscno/esec/server/middleware"
	"github.com/mscno/esec/server/model"
)

func MockUserHasRoleInRepo(token string, orgRepo model.OrgRepo, role string) bool {
	if token == "testtoken" && orgRepo == "foo/bar" {
		return true
	}
	return false
}

func MockTokenValidator(token string) (middleware.GithubUser, bool) {
	if token == "testtoken" {
		return middleware.GithubUser{Login: "testuser", ID: 42, Token: token}, true
	}
	return middleware.GithubUser{}, false
}
