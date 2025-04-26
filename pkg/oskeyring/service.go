package oskeyring

import (
	"errors"
	"fmt"
	"sync"

	keyringlib "github.com/zalando/go-keyring"
)

// ErrNotFound is returned by Get when the requested secret is not found.
var ErrNotFound = errors.New("secret not found in keyring")

// Service defines an interface for interacting with the operating system's keyring.
// This abstracts the underlying keyring implementation.
type Service interface {
	// Get retrieves a secret for a given service and user.
	// It returns ErrNotFound if the secret is not found.
	Get(service, user string) (string, error)
	// Set stores a secret for a given service and user.
	Set(service, user, password string) error
	// Delete removes a secret for a given service and user.
	// It should not return an error if the secret does not exist.
	Delete(service, user string) error
}

// DefaultService is the default implementation of the Service interface using the zalando/go-keyring library.
type DefaultService struct{}

// NewDefaultService creates a new DefaultService.
func NewDefaultService() *DefaultService {
	return &DefaultService{}
}

// Get implements the Service interface.
func (s *DefaultService) Get(service, user string) (string, error) {
	secret, err := keyringlib.Get(service, user)
	if err != nil {
		if errors.Is(err, keyringlib.ErrNotFound) {
			return "", ErrNotFound // Return package-level error
		}
		return "", fmt.Errorf("failed to get secret from OS keyring: %w", err)
	}
	return secret, nil
}

// Set implements the Service interface.
func (s *DefaultService) Set(service, user, password string) error {
	return keyringlib.Set(service, user, password)
}

// Delete implements the Service interface.
func (s *DefaultService) Delete(service, user string) error {
	// zalando/go-keyring Delete does not return an error if not found.
	return keyringlib.Delete(service, user)
}

// Ensure DefaultService implements Service.
var _ Service = (*DefaultService)(nil)

// --- Memory Implementation ---

// MemoryService is an in-memory implementation of the Service interface for testing.
type MemoryService struct {
	mu    sync.RWMutex
	store map[string]map[string]string // service -> user -> secret
}

// NewMemoryService creates a new MemoryService.
func NewMemoryService() *MemoryService {
	return &MemoryService{
		store: make(map[string]map[string]string),
	}
}

// Get implements the Service interface.
func (s *MemoryService) Get(service, user string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if users, ok := s.store[service]; ok {
		if secret, ok := users[user]; ok {
			return secret, nil
		}
	}
	return "", ErrNotFound
}

// Set implements the Service interface.
func (s *MemoryService) Set(service, user, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.store[service]; !ok {
		s.store[service] = make(map[string]string)
	}
	s.store[service][user] = password
	return nil
}

// Delete implements the Service interface.
func (s *MemoryService) Delete(service, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if users, ok := s.store[service]; ok {
		delete(users, user)
		// Optional: clean up service map if empty
		if len(users) == 0 {
			delete(s.store, service)
		}
	}
	return nil
}

// Ensure MemoryService implements Service.
var _ Service = (*MemoryService)(nil)
