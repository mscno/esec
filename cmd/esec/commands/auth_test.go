package commands

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/mscno/esec/pkg/auth"
	"github.com/mscno/esec/pkg/oskeyring"
)

func TestAuthSync(t *testing.T) {
	port := testServer(t)
	time.Sleep(time.Second * 1)

	ctx := &cliCtx{
		Context: context.Background(),
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		OSKeyring: oskeyring.NewMemoryService(),
	}

	authGen := AuthGenerateKeypairCmd{}
	err := authGen.Run(ctx)
	assert.NoError(t, err)

	ctx.OSKeyring.Set(auth.ServiceName, auth.AccountName, "testtoken")

	cmd := AuthSyncCmd{}
	err = cmd.Run(ctx, &AuthCmd{}, &CloudCmd{ServerURL: "http://localhost:" + strconv.Itoa(port)})
	assert.NoError(t, err)

}
