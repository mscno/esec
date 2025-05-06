package commands

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/pkg/auth"

	// "github.com/alecthomas/assert/v2" // Uncomment when adding assertions
	"github.com/mscno/esec/pkg/oskeyring"
)

func TestShare(t *testing.T) {
	svc, port := testServer(t)
	time.Sleep(time.Second * 1)
	ctx := &cliCtx{
		Context: context.Background(),
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		OSKeyring: oskeyring.NewMemoryService(),
	}
	ctx.OSKeyring.Set(auth.ServiceName, auth.GithubToken, "testtoken")
	ctx.OSKeyring.Set(auth.ServiceName, auth.GithubUserID, "42")
	ctx.OSKeyring.Set(auth.ServiceName, auth.GithubLogin, "testuser")

	ctx2 := &cliCtx{
		Context: context.Background(),
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		OSKeyring: oskeyring.NewMemoryService(),
	}

	ctx2.OSKeyring.Set(auth.ServiceName, auth.GithubToken, "testtoken2")
	ctx2.OSKeyring.Set(auth.ServiceName, auth.GithubUserID, "43")
	ctx2.OSKeyring.Set(auth.ServiceName, auth.GithubLogin, "testuser2")

	cloudCmd := &CloudCmd{ServerURL: "http://localhost:" + strconv.Itoa(port), ProjectDir: t.TempDir()}
	cloudCmd2 := &CloudCmd{ServerURL: "http://localhost:" + strconv.Itoa(port), ProjectDir: t.TempDir()}
	fmt.Println(svc)
	t.Run("user1", func(t *testing.T) {
		authGen := AuthGenerateKeypairCmd{}
		err := authGen.Run(ctx)
		assert.NoError(t, err)

		cmd := AuthSyncCmd{}
		err = cmd.Run(ctx, &AuthCmd{}, cloudCmd)
		assert.NoError(t, err)

		createCmd := ProjectsCreateCmd{"foo/bar"}
		err = createCmd.Run(ctx, cloudCmd)
		assert.NoError(t, err)
	})

	t.Run("user2", func(t *testing.T) {
		authGen := AuthGenerateKeypairCmd{}
		err := authGen.Run(ctx2)
		assert.NoError(t, err)

		cmd := AuthSyncCmd{}
		err = cmd.Run(ctx2, &AuthCmd{}, cloudCmd2)
		assert.NoError(t, err)
	})

	t.Run("user1 sync", func(t *testing.T) {
		os.WriteFile(path.Join(cloudCmd.ProjectDir, ".esec-keyring"), bytes.NewBufferString(`
ESEC_PRIVATE_KEY=7dfbd3bc0f2ae2e624e7a60bddf8a50aa84d3877b6fb7555db78248fc8b80f10
`).Bytes(), 0644)

		cmd := SyncPushCmd{}
		err := cmd.Run(ctx, cloudCmd)
		assert.NoError(t, err)
	})

	t.Run("user1 sync pull", func(t *testing.T) {
		syncPush := SyncPullCmd{}
		err := syncPush.Run(ctx, cloudCmd)
		assert.NoError(t, err)

		newFile, err := os.ReadFile(path.Join(cloudCmd.ProjectDir, ".esec-keyring"))
		assert.NoError(t, err)
		assert.Equal(t, string(newFile), `###########################################################
### Private key file - Do not commit to version control ###
###########################################################

### Private Keys
ESEC_PRIVATE_KEY=7dfbd3bc0f2ae2e624e7a60bddf8a50aa84d3877b6fb7555db78248fc8b80f10
`)

	})

	t.Run("user2 sync pull", func(t *testing.T) {
		cmd := SyncPullCmd{}
		err := cmd.Run(ctx2, cloudCmd2)
		assert.Error(t, err)
	})

	t.Run("user1 share", func(t *testing.T) {
		svc := svc
		_ = svc
		cmd := ShareCmd{KeyName: "ESEC_PRIVATE_KEY", Users: []string{"43"}}
		err := cmd.Run(ctx, cloudCmd)
		assert.NoError(t, err)
	})

	t.Run("user2 sync pull", func(t *testing.T) {
		os.WriteFile(path.Join(cloudCmd2.ProjectDir, ".esec-project"), bytes.NewBufferString(`
ESEC_PROJECT=foo/bar
`).Bytes(), 0644)

		cmd := SyncPullCmd{}
		err := cmd.Run(ctx2, cloudCmd2)
		assert.NoError(t, err)

		newFile, err := os.ReadFile(path.Join(cloudCmd2.ProjectDir, ".esec-keyring"))
		assert.NoError(t, err)
		assert.Equal(t, string(newFile), `###########################################################
### Private key file - Do not commit to version control ###
###########################################################

### Private Keys
ESEC_PRIVATE_KEY=7dfbd3bc0f2ae2e624e7a60bddf8a50aa84d3877b6fb7555db78248fc8b80f10
`)
	})

	t.Run("user1 unshare to user 2", func(t *testing.T) {
		svc := svc
		_ = svc
		cmd := UnshareCmd{KeyName: "ESEC_PRIVATE_KEY", Users: []string{"43"}}
		err := cmd.Run(ctx, cloudCmd)
		assert.NoError(t, err)
	})

	t.Run("user2 sync pull after unshare", func(t *testing.T) {
		cmd := SyncPullCmd{}
		err := cmd.Run(ctx2, cloudCmd2)
		assert.Error(t, err)
	})

}
