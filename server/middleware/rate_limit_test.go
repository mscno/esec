package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimiter(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		expectStatus int
		numRequests  int
		sleep        time.Duration
		burst        int
		limit        rate.Limit
	}{
		{
			name:         "within rate limit",
			ip:           "192.168.1.1",
			expectStatus: http.StatusOK,
			numRequests:  20,
			limit:        rate.Every(time.Millisecond),
			burst:        20,
			sleep:        time.Millisecond,
		},
		{
			name:         "exceed rate limit per second",
			ip:           "192.168.1.1",
			expectStatus: http.StatusTooManyRequests,
			numRequests:  65,
			limit:        rate.Every(time.Millisecond),
			burst:        60,
			sleep:        0,
		},
		{
			name:         "ok within limit as limits refresh 1",
			ip:           "192.168.1.1",
			expectStatus: http.StatusOK,
			numRequests:  10,
			limit:        rate.Every(time.Millisecond),
			burst:        1,
			sleep:        time.Millisecond,
		},
		{
			name:         "ok within limit as limits refresh 2",
			ip:           "192.168.1.1",
			expectStatus: http.StatusOK,
			numRequests:  11,
			limit:        rate.Every(time.Millisecond),
			burst:        10,
			sleep:        time.Millisecond / 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new rate limiter
			rl := NewRateLimiter(slog.Default(), func(r *http.Request) string {
				return r.RemoteAddr // Use IP address for rate limit
			}, tc.limit, tc.burst)

			// Create a simple handler that returns 200 OK
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test"))
			})

			// Wrap the test handler with the rate limiter middleware
			handler := rl.Limit(testHandler)

			// Set up request and response recorder
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tc.ip

			var rec *httptest.ResponseRecorder
			for i := 0; i < tc.numRequests; i++ {
				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				time.Sleep(tc.sleep)
			}

			// Assert the final response status
			assert.Equal(t, tc.expectStatus, rec.Code)
		})
	}
}
