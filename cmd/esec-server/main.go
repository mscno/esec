package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/mscno/esec/gen/proto/go/esec/esecpbconnect"
	"github.com/mscno/esec/server/middleware"
	"go.etcd.io/bbolt"
	"golang.org/x/time/rate"

	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/stores"
)

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Choose store implementation
	var projectStore server.ProjectStore
	var userStore server.UserStore
	var orgStore server.OrganizationStore
	storeType := os.Getenv("ESEC_STORE")
	if storeType == "bolt" {
		boltPath := os.Getenv("ESEC_BOLT_PATH")
		if boltPath == "" {
			boltPath = "esec.db"
		}
		db, err := bbolt.Open(boltPath, 0600, nil)
		if err != nil {
			log.Fatalf("failed to open BoltDB: %v", err)
		}
		defer db.Close()

		projectStore = stores.NewBoltProjectStore(db)
		userStore = stores.NewBoltUserStore(db)
		//orgStore = stores.NewBoltOrganizationStore(db)
		logger.Info(fmt.Sprintf("Using BoltDB store at %s", boltPath))

	} else if storeType == "datastore" {
		datastoreProject := os.Getenv("ESEC_DATASTORE_PROJECT")
		datastoreDatabase := os.Getenv("ESEC_DATASTORE_DATABASE")

		dsClient, err := datastore.NewClientWithDatabase(ctx, datastoreProject, datastoreDatabase)
		if err != nil {
			log.Fatalf("failed to create datastore client: %v", err)
		}
		projectStore = stores.NewProjectDataStore(logger, dsClient)
		userStore = stores.NewUserDataStore(logger, dsClient)
		orgStore = stores.NewOrganizationDataStore(logger, dsClient)
		logger.Info(fmt.Sprintf("Using datastore store at %s", datastoreProject))
	} else {
		projectStore = stores.NewInMemoryProjectStore()
		userStore = stores.NewInMemoryUserStore()
		orgStore = stores.NewInMemoryOrganizationStore()
		logger.Info("Using in-memory store")
	}

	srv := server.NewServer(projectStore, userStore, orgStore, logger, nil)

	path, h := esecpbconnect.NewEsecServiceHandler(srv)

	connectSrv := server.NewConnectServer()
	connectSrv.Use(append(globalMiddleware(logger), middleware.WithGitHubAuth(middleware.ValidateGitHubToken))...)
	connectSrv.Handle(path, h)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	logger.Info(fmt.Sprintf("Esec Sync Server listening on %s", addr))
	if err := http.ListenAndServe(addr, connectSrv); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func globalMiddleware(logger *slog.Logger) []func(http.Handler) http.Handler {
	const (
		defaultRateLimit = time.Second / 5
		defaultRateBurst = 20
	)

	limiter := middleware.NewRateLimiter(
		logger,
		middleware.IPAddressKeyFunc,
		rate.Every(defaultRateLimit),
		defaultRateBurst,
		middleware.WithSkipper(func(r *http.Request) bool {
			if flag.Lookup("test.v") == nil {
				return false
			} else {
				return true
			}
		}),
	)

	return []func(http.Handler) http.Handler{
		middleware.RecoveryMiddleware,
		middleware.WithCORS(logger),
		middleware.WithLogger(logger),
		limiter.Limit,
	}

}
