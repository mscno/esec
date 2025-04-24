package middleware

import (
	"log/slog"
	"net/http"
)

// WithLogger adds request logging

func WithLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//logger.Info("request",
			//	"remote_addr", r.RemoteAddr,
			//	"method", r.Method,
			//	"url", r.URL.String(),
			//)
			next.ServeHTTP(w, r)
		})
	}
}
