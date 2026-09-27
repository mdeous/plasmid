package store

import (
	"fmt"
	"sync"
	"testing"

	"github.com/crewjam/saml/samlidp"
)

// hammer runs concurrent readers and writers against the store, mirroring what
// the dashboard's stats polling does while SAML logins write sessions.
func hammer(t *testing.T, s samlidp.Store) {
	t.Helper()

	const workers = 8
	const iterations = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("/sessions/w%d-%d", w, i)
				if err := s.Put(key, &samlidp.User{Name: key}); err != nil {
					t.Errorf("Put(%s): %v", key, err)
					return
				}
				if err := s.Delete(key); err != nil {
					t.Errorf("Delete(%s): %v", key, err)
					return
				}
			}
		}(w)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := s.List("/sessions/"); err != nil {
					t.Errorf("List: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSyncStoreConcurrentListAndWrite(t *testing.T) {
	hammer(t, New(&samlidp.MemoryStore{}))
}

func TestSyncStoreRoundTrip(t *testing.T) {
	s := New(&samlidp.MemoryStore{})

	if err := s.Put("/users/alice", &samlidp.User{Name: "alice"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var got samlidp.User
	if err := s.Get("/users/alice", &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "alice" {
		t.Errorf("Get: expected name %q, got %q", "alice", got.Name)
	}

	names, err := s.List("/users/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "alice" {
		t.Errorf("List: expected [alice], got %v", names)
	}

	if err := s.Delete("/users/alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Get("/users/alice", &got); err != samlidp.ErrNotFound {
		t.Errorf("Get after Delete: expected ErrNotFound, got %v", err)
	}
}
