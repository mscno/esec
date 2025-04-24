package middleware

import (
	"golang.org/x/time/rate"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	extractKey KeyFunc
	limiters   map[string]*rate.Limiter
	mu         sync.Mutex
	rate       rate.Limit
	burst      int
	skipper    Skipper
	logger     *slog.Logger
}

// KeyFunc extracts a key from the request for rate limiting
type KeyFunc func(*http.Request) string

// Skipper determines if a request should skip rate limiting
type Skipper func(*http.Request) bool

// RateLimiterOption configures a RateLimiter
type RateLimiterOption func(*RateLimiter)

// WithSkipper sets a skipper function for the rate limiter
func WithSkipper(skipper Skipper) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.skipper = skipper
	}
}

// IPAddressKeyFunc returns the IP address from the request
func IPAddressKeyFunc(r *http.Request) string {
	return r.RemoteAddr
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(logger *slog.Logger, keyFunc KeyFunc, limit rate.Limit, burst int, options ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		extractKey: keyFunc,
		limiters:   make(map[string]*rate.Limiter),
		rate:       limit,
		burst:      burst,
		skipper:    func(*http.Request) bool { return false },
		logger:     logger,
	}

	for _, opt := range options {
		opt(rl)
	}
	go rl.cleanup()
	return rl
}

// cleanup periodically removes unused rate limiters to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for key, limiter := range rl.limiters {
			if limiter.Allow() {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// getLimiter gets or creates a rate limiter for the given key
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[key] = limiter
	}
	return limiter
}

// Limit implements the rate limiting middleware
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl.skipper(r) {
			next.ServeHTTP(w, r)
			return
		}

		key := rl.extractKey(r)
		limiter := rl.getLimiter(key)

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			rl.logger.Warn("rate limit exceeded",
				"remote_addr", r.RemoteAddr,
				"method", r.Method,
				"url", r.URL.Path,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

//
//type RateLimiter struct {
//	mu     sync.Mutex
//	m      map[string]*rate.Limiter
//	limit  rate.Limit
//	burst  int
//	skipFn func(*http.Request) bool
//	keyFn  func(*http.Request) string
//}
//
//type Option func(*RateLimiter)
//
//func WithSkipper(skipFn func(*http.Request) bool) func(*RateLimiter) {
//	return func(rl *RateLimiter) {
//		rl.skipFn = skipFn
//	}
//}
//
//func defaultSkipper(r *http.Request) bool {
//	return false
//}
//
//// NewRateLimiter creates a new RateLimiter for use in http.Handler middleware
//func NewRateLimiter(keyFn func(*http.Request) string, limit rate.Limit, burst int, options ...Option) *RateLimiter {
//	rl := &RateLimiter{
//		m:      make(map[string]*rate.Limiter),
//		limit:  limit,
//		burst:  burst,
//		keyFn:  keyFn,
//		skipFn: defaultSkipper,
//	}
//
//	for _, option := range options {
//		option(rl)
//	}
//
//	go rl.cleanup()
//	return rl
//}
//
//func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
//	rl.mu.Lock()
//	defer rl.mu.Unlock()
//
//	limiter, exists := rl.m[key]
//	if !exists {
//		limiter = rate.NewLimiter(rl.limit, rl.burst)
//		rl.m[key] = limiter
//	}
//	return limiter
//}
//
//func (rl *RateLimiter) cleanup() {
//	for {
//		time.Sleep(time.Minute)
//		rl.mu.Lock()
//		for key, limiter := range rl.m {
//			if limiter.Allow() {
//				delete(rl.m, key)
//			}
//		}
//		rl.mu.Unlock()
//	}
//}
//
//// Limit is the middleware that applies rate limiting to the incoming requests
//func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		if rl.skipFn(r) {
//			next.ServeHTTP(w, r)
//			return
//		}
//
//		key := rl.keyFn(r)
//		limiter := rl.getLimiter(key)
//		if !limiter.Allow() {
//			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
//			return
//		}
//
//		next.ServeHTTP(w, r)
//	})
//}
