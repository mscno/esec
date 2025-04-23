package main

import (
	"github.com/mscno/esec/server/middleware"
	"log"
	"net/http"
	"os"

	"github.com/go-michi/michi"
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

	h := server.NewHandler(s, userStore, nil)

	mux := michi.NewRouter()

	mux.Use(middleware.PanicRecoveryMiddleware, middleware.LoggingMiddleware)
	mux.Use(middleware.WithGitHubAuth(middleware.ValidateGitHubToken))
	// Project creation (POST)
	mux.HandleFunc("POST /api/v1/projects", h.CreateProject)

	// Project keys-per-user (PUT)
	mux.HandleFunc("PUT /api/v1/projects/{org}/{repo}/keys-per-user", h.ProjectKeysPerUserPut)

	// Project keys-per-user (GET)
	mux.HandleFunc("GET /api/v1/projects/{org}/{repo}/keys-per-user", h.ProjectKeysPerUserGet)

	// User registration (POST)
	mux.HandleFunc("POST /api/v1/users/register", h.HandleUserRegister)

	addr := ":8080"
	log.Printf("Esec Sync Server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
