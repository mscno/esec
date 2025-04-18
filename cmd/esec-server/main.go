package main

import (
	"log"
	"net/http"
	"os"

	"github.com/mscno/esec/server"
	"github.com/mscno/esec/server/stores"
)

func main() {
	// --- User store ---
	userStore := stores.NewMemoryUserStore()

	// Choose store implementation
	var s stores.Store
	storeType := os.Getenv("ESEC_STORE")
	if storeType == "bolt" {
		boltPath := os.Getenv("ESEC_BOLT_PATH")
		if boltPath == "" {
			boltPath = "esec.db"
		}
		boltStore, err := stores.NewBoltStore(boltPath)
		if err != nil {
			log.Fatalf("failed to open BoltDB: %v", err)
		}
		defer boltStore.Close()
		s = boltStore
		log.Printf("Using BoltDB store at %s", boltPath)
	} else {
		s = stores.NewMemoryStore()
		log.Printf("Using in-memory store")
	}

	h := server.NewHandler(s, userStore)

	mux := http.NewServeMux()

	// Project creation (POST)
	mux.Handle("POST /api/v1/projects", server.LoggingMiddleware(server.WithGitHubAuth(http.HandlerFunc(h.CreateProject), true)))

	// Project keys-per-user (PUT)
	mux.Handle("PUT /api/v1/projects/{project}/keys-per-user", server.LoggingMiddleware(server.WithGitHubAuth(http.HandlerFunc(h.ProjectKeysPerUser), true)))

	// Project keys-per-user (GET)
	mux.Handle("GET /api/v1/projects/{project}/keys-per-user", server.LoggingMiddleware(server.WithGitHubAuth(http.HandlerFunc(h.ProjectKeysPerUser), true)))

	// User registration (POST)
	mux.Handle("POST /api/v1/users/register", server.LoggingMiddleware(http.HandlerFunc(h.HandleUserRegister)))

	addr := ":8080"
	log.Printf("Esec Sync Server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
