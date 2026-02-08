package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	idp "github.com/crewjam/saml/samlidp"
)

func TestNew_ValidURL(t *testing.T) {
	c, err := New("http://localhost:8080")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c == nil {
		t.Fatal("expected client to be non-nil")
	}
	if c.BaseUrl.String() != "http://localhost:8080" {
		t.Fatalf("expected base URL 'http://localhost:8080', got '%s'", c.BaseUrl.String())
	}
	if c.UserAgent != "plasmid" {
		t.Fatalf("expected user agent 'plasmid', got '%s'", c.UserAgent)
	}
}

func TestNew_InvalidURL(t *testing.T) {
	_, err := New("://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestUserList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["admin","test"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	users, err := c.UserList()
	if err != nil {
		t.Fatalf("unexpected error listing users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0] != "admin" {
		t.Errorf("expected first user 'admin', got '%s'", users[0])
	}
	if users[1] != "test" {
		t.Errorf("expected second user 'test', got '%s'", users[1])
	}
}

func TestUserAdd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("error reading request body: %v", err)
		}
		var user idp.User
		if err := json.Unmarshal(body, &user); err != nil {
			t.Fatalf("request body is not valid JSON: %v", err)
		}
		if user.Name != "admin" {
			t.Errorf("expected user name 'admin', got '%s'", user.Name)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	password := "secret"
	user := &idp.User{
		Name:              "admin",
		PlaintextPassword: &password,
		Email:             "admin@example.com",
	}
	err = c.UserAdd(user)
	if err != nil {
		t.Fatalf("unexpected error adding user: %v", err)
	}
}

func TestUserGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"admin","email":"admin@example.com"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	user, err := c.UserGet("admin")
	if err != nil {
		t.Fatalf("unexpected error getting user: %v", err)
	}
	if user.Name != "admin" {
		t.Errorf("expected user name 'admin', got '%s'", user.Name)
	}
	if user.Email != "admin@example.com" {
		t.Errorf("expected email 'admin@example.com', got '%s'", user.Email)
	}
}

func TestUserDel(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users":["admin","test"]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.UserDel("admin")
	if err != nil {
		t.Fatalf("unexpected error deleting user: %v", err)
	}
}

func TestUserDel_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["admin"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.UserDel("nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent user, got nil")
	}
}

func TestServiceList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"services":["myapp","otherapp"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	services, err := c.ServiceList()
	if err != nil {
		t.Fatalf("unexpected error listing services: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0] != "myapp" {
		t.Errorf("expected first service 'myapp', got '%s'", services[0])
	}
	if services[1] != "otherapp" {
		t.Errorf("expected second service 'otherapp', got '%s'", services[1])
	}
}

func TestServiceDel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"services":["myapp"]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.ServiceDel("myapp")
	if err != nil {
		t.Fatalf("unexpected error deleting service: %v", err)
	}
}

func TestServiceDel_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"services":["myapp"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.ServiceDel("nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent service, got nil")
	}
}

func TestSessionList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sessions":["sess1","sess2","sess3"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	sessions, err := c.SessionList()
	if err != nil {
		t.Fatalf("unexpected error listing sessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(sessions))
	}
	if sessions[0] != "sess1" {
		t.Errorf("expected first session 'sess1', got '%s'", sessions[0])
	}
}

func TestSessionGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"sess1"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	session, err := c.SessionGet("sess1")
	if err != nil {
		t.Fatalf("unexpected error getting session: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be non-nil")
	}
}

func TestSessionDel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sessions":["sess1"]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.SessionDel("sess1")
	if err != nil {
		t.Fatalf("unexpected error deleting session: %v", err)
	}
}

func TestSessionDel_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sessions":["sess1"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.SessionDel("nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent session, got nil")
	}
}

func TestShortcutList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"shortcuts":["sc1","sc2"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	shortcuts, err := c.ShortcutList()
	if err != nil {
		t.Fatalf("unexpected error listing shortcuts: %v", err)
	}
	if len(shortcuts) != 2 {
		t.Fatalf("expected 2 shortcuts, got %d", len(shortcuts))
	}
	if shortcuts[0] != "sc1" {
		t.Errorf("expected first shortcut 'sc1', got '%s'", shortcuts[0])
	}
	if shortcuts[1] != "sc2" {
		t.Errorf("expected second shortcut 'sc2', got '%s'", shortcuts[1])
	}
}

func TestShortcutAdd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("error reading request body: %v", err)
		}
		var sc idp.Shortcut
		if err := json.Unmarshal(body, &sc); err != nil {
			t.Fatalf("request body is not valid JSON: %v", err)
		}
		if sc.Name != "myshortcut" {
			t.Errorf("expected shortcut name 'myshortcut', got '%s'", sc.Name)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	shortcut := &idp.Shortcut{
		Name:              "myshortcut",
		ServiceProviderID: "https://sp.example.com/saml/metadata",
	}
	err = c.ShortcutAdd(shortcut)
	if err != nil {
		t.Fatalf("unexpected error adding shortcut: %v", err)
	}
}

func TestShortcutDel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"shortcuts":["myshortcut"]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.ShortcutDel("myshortcut")
	if err != nil {
		t.Fatalf("unexpected error deleting shortcut: %v", err)
	}
}

func TestShortcutDel_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"shortcuts":["myshortcut"]}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = c.ShortcutDel("nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent shortcut, got nil")
	}
}

func TestRequest_UserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "plasmid" {
			t.Errorf("expected User-Agent 'plasmid', got '%s'", ua)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_, _, err = c.request(http.MethodGet, "/test", nil, http.StatusOK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequest_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_, _, err = c.request(http.MethodGet, "/test", nil, http.StatusOK)
	if err == nil {
		t.Fatal("expected error for unexpected status code, got nil")
	}
}
