package commands

import (
	"connectrpc.com/connect"
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/oskeyring"
)

func TestProjects(t *testing.T) {
	_, port := testServer(t)
	time.Sleep(time.Second * 1)

	ctx := &cliCtx{
		Context: context.Background(),
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		OSKeyring: oskeyring.NewMemoryService(),
	}
	cloudCmd := &CloudCmd{ServerURL: "http://localhost:" + strconv.Itoa(port), ProjectDir: t.TempDir()}
	ctx.OSKeyring.Set(auth.ServiceName, auth.GithubToken, "testtoken")

	cmd := ProjectsCreateCmd{"mscno/esec"}
	err := cmd.Run(ctx, cloudCmd)
	assert.Error(t, err)
	var cErr *connect.Error
	assert.True(t, errors.As(err, &cErr))
	assert.Equal(t, connect.CodePermissionDenied.String(), cErr.Code().String())

	cmd = ProjectsCreateCmd{"foo/bar"}
	err = cmd.Run(ctx, cloudCmd)
	assert.NoError(t, err)

	cmdInfo := ProjectsInfoCmd{"foo/bar"}
	err = cmdInfo.Run(ctx, cloudCmd)
	assert.Error(t, err)

}
