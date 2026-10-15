package secretstore

import "sync"

// Memory is an in-process Store for tests.
type Memory struct {
	mu   sync.Mutex
	data map[string]string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{data: map[string]string{}} }

// Backend implements Store.
func (m *Memory) Backend() string { return "memory" }

// HardwareBound implements Store.
func (m *Memory) HardwareBound() bool { return false }

// Get implements Store.
func (m *Memory) Get(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Store.
func (m *Memory) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[name] = value
	return nil
}

// Delete implements Store.
func (m *Memory) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, name)
	return nil
}
