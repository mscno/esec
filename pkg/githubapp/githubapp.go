package githubapp

import (
	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v71/github"
	"net/http"
	"time"
)

// NewInstallationClient creates a GitHub client authenticated as an app installation.
// privateKey should be the PEM-encoded content of the app's private key.
func NewInstallationClient(appID int64, installationID int64, privateKey []byte, enterpriseURL ...string) (*github.Client, error) {
	tr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, privateKey)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second, // Increased timeout for potentially slower enterprise instances
	}

	if len(enterpriseURL) > 0 && enterpriseURL[0] != "" {
		// For GitHub Enterprise
		client, err := github.NewEnterpriseClient(enterpriseURL[0], enterpriseURL[0], httpClient)
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	return github.NewClient(httpClient), nil
}
