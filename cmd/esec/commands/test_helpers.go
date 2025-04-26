package commands

import (
	"log/slog"
	"net/http"
	"strconv"
	"testing"

	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/middleware"
	"github.com/mscno/esec/server/stores"
	"github.com/mscno/esec/testutl"
)

func testServer(t *testing.T) int {
	esecSvc := server.NewServer(
		stores.NewInMemoryProjectStore(),
		stores.NewInMemoryUserStore(),
		slog.Default(),
		testutl.MockUserHasRoleInRepo,
	)
	path, h := esecpbconnect.NewEsecServiceHandler(esecSvc)
	srv := server.NewConnectServer()
	srv.Use(middleware.WithGitHubAuth(testutl.MockTokenValidator))
	srv.Handle(path, h)

	port := testutl.GetPort()

	go func() {
		slog.Info("Starting server on port", "port", port)
		srv.Server.Addr = ":" + strconv.Itoa(port)
		if err := srv.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error(err.Error())
		}
	}()

	t.Cleanup(func() {
		srv.Server.Close()
	})

	return port
}
