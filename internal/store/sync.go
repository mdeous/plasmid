package store

import (
	"sync"

	"github.com/crewjam/saml/samlidp"
)

// SyncStore serializes access to a samlidp.Store. It exists because
// samlidp.MemoryStore.List iterates its map without taking the lock its
// writers hold, so polling the dashboard while a login writes a session
// trips Go's fatal "concurrent map read and map write".
type SyncStore struct {
	mu    sync.RWMutex
	inner samlidp.Store
}

var _ samlidp.Store = (*SyncStore)(nil)

func New(inner samlidp.Store) *SyncStore {
	return &SyncStore{inner: inner}
}

func (s *SyncStore) Get(key string, value any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner.Get(key, value)
}

func (s *SyncStore) Put(key string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Put(key, value)
}

func (s *SyncStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Delete(key)
}

func (s *SyncStore) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner.List(prefix)
}
