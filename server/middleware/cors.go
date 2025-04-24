package middleware

import (
	connectcors "connectrpc.com/cors"
	"fmt"
	"github.com/rs/cors"
	"log/slog"
	"net/http"
)

type corsLogger struct {
	logger *slog.Logger
}

func (c *corsLogger) Printf(format string, args ...interface{}) {
	c.logger.Debug(fmt.Sprintf("CORS: %s", fmt.Sprintf(format, args...)))
}

// WithCORS adds CORS middleware
func WithCORS(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		middleware := cors.New(cors.Options{
			AllowedOrigins: []string{"*"},
			AllowedMethods: connectcors.AllowedMethods(),
			AllowedHeaders: []string{"*"},
			ExposedHeaders: []string{"*"},
			//Logger:         &corsLogger{logger: logger},
		})
		return middleware.Handler(h)
	}
}
