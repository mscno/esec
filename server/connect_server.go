package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-michi/michi"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"log/slog"
)

const (
	maxHeaderBytes    = 1 << 20
	readTimeout       = 30 * time.Second
	readHeaderTimeout = 5 * time.Second
	writeTimeout      = 30 * time.Second
	defaultRateLimit  = time.Second / 5
	defaultRateBurst  = 20
)

// Shutdown gracefully stops the server
func (c *ConnectServer) Shutdown() error {
	slog.Debug("shutting down server")
	err := c.Server.Shutdown(context.Background())
	if err != nil {
		slog.Error("error shutting down server:", "error", err)
		return err
	}
	return nil
}

// ServeHTTP implements the http.Handler interface
func (c *ConnectServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.Server.Handler.ServeHTTP(w, r)
}

func (c *ConnectServer) Handle(path string, handler http.Handler) {
	c.routesAdded = true
	c.ServeMux.Handle(path, handler)
}

// fallbackHandler routes requests either to the mux (for Connect/gRPC) or the router
type fallbackHandler struct {
	mux        *http.ServeMux
	router     *michi.Router
	h2cHandler http.Handler
}

// ServeHTTP implements the http.Handler interface for fallbackHandler
func (m *fallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, pattern := m.mux.Handler(r); pattern != "" {
		m.h2cHandler.ServeHTTP(w, r)
	} else {
		m.router.ServeHTTP(w, r)
	}
}

type ConnectServer struct {
	ServeMux *http.ServeMux
	Server   *http.Server
	Router   *michi.Router

	// Add fields to store middleware and the fallback handler
	middleware  []func(http.Handler) http.Handler
	fbHandler   *fallbackHandler
	routesAdded bool
}

// NewConnectServer creates a new ConnectServer instance
func NewConnectServer() *ConnectServer {
	mux := http.NewServeMux()
	router := michi.NewRouter()
	h2cHandler := h2c.NewHandler(mux, &http2.Server{})

	fbHandler := &fallbackHandler{
		mux:        mux,
		router:     router,
		h2cHandler: h2cHandler,
	}

	// Create the server with no middleware initially
	server := &http.Server{
		Handler:           fbHandler, // Use fbHandler directly initially
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	return &ConnectServer{
		ServeMux:   mux,
		Server:     server,
		Router:     router,
		middleware: []func(http.Handler) http.Handler{},
		fbHandler:  fbHandler,
	}
}

// Use adds middleware to the server
func (s *ConnectServer) Use(mw ...func(http.Handler) http.Handler) {
	if s.routesAdded {
		panic("cannot add middleware after routes are registered")
	}
	s.middleware = append(s.middleware, mw...)

	// Rebuild the handler chain with the updated middleware
	s.rebuildHandlerChain()
}

// rebuildHandlerChain rebuilds the HTTP handler chain with current middleware
func (s *ConnectServer) rebuildHandlerChain() {
	var handler http.Handler = s.fbHandler
	s.Server.Handler = applyMiddleware(handler, s.middleware...)
}

type middlewareFn func(http.Handler) http.Handler

func applyMiddleware(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply middleware in reverse order so the first middleware in the slice
	// is the outermost one (first to process the request)
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
