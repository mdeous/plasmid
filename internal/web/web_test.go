package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	internalsml "github.com/mdeous/plasmid/internal/saml"
)

func TestValidateEntityName(t *testing.T) {
	valid := []string{"alice", "test-sp", "sp_1", "a.b", "Admin@example.com"}
	for _, name := range valid {
		if err := validateEntityName(name); err != nil {
			t.Errorf("validateEntityName(%q): unexpected error %v", name, err)
		}
	}

	invalid := []string{"", "a/b", "with space", "tab\there", "new\nline"}
	for _, name := range invalid {
		if err := validateEntityName(name); err == nil {
			t.Errorf("validateEntityName(%q): expected an error, got nil", name)
		}
	}
}

// Sessions created by the upstream library get base64 IDs, which can contain
// characters that need escaping in a URL path.
func TestHandleSessionDeleteEscapedID(t *testing.T) {
	store := &samlidp.MemoryStore{}
	id := "abc/def+ghi="
	if err := store.Put("/sessions/"+id, &saml.Session{ID: id}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	h := &WebHandler{store: store, logger: slog.Default()}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /ui/sessions/{id}", h.handleSessionDelete)

	req := httptest.NewRequest("DELETE", "/ui/sessions/"+url.QueryEscape(id), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("DELETE session: expected 200, got %d", w.Code)
	}
	var session saml.Session
	if err := store.Get("/sessions/"+id, &session); err != samlidp.ErrNotFound {
		t.Errorf("session was not deleted: Get returned %v", err)
	}
}

// Guards the template sets: a partial that is registered in one set but not the
// other, or a field renamed out from under a template, only shows up at render
// time.
func TestRenderAllPages(t *testing.T) {
	h, err := NewWebHandler(&samlidp.MemoryStore{}, nil, slog.Default(), "http://127.0.0.1:8000", nil)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	h.SetTamperConfig(internalsml.NewTamperConfig())
	h.SetInspector(internalsml.NewInspector(10))
	h.SetMetadataXML("<EntityDescriptor/>")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	h.RegisterInspectorRoutes(mux)

	pages := []string{
		"/ui/", "/ui/users", "/ui/services", "/ui/sessions",
		"/ui/shortcuts", "/ui/settings", "/ui/inspector", "/ui/tamper",
	}
	for _, path := range pages {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("GET %s: expected 200, got %d; body: %s", path, w.Code, w.Body.String())
			continue
		}
		// renderPage streams, so a mid-render failure still returns 200 with a
		// truncated body. Check the document actually finished.
		if !strings.Contains(w.Body.String(), "</html>") {
			t.Errorf("GET %s: page render did not complete", path)
		}
	}

	partials := []string{"/ui/api/stats", "/ui/inspector/exchanges", "/ui/sessions/list"}
	for _, path := range partials {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: expected 200, got %d; body: %s", path, w.Code, w.Body.String())
		}
	}
}

// The tamper page must round-trip every option, including ones added later.
func TestTamperSaveRoundTrip(t *testing.T) {
	h, err := NewWebHandler(&samlidp.MemoryStore{}, nil, slog.Default(), "http://127.0.0.1:8000", nil)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	config := internalsml.NewTamperConfig()
	h.SetTamperConfig(config)

	mux := http.NewServeMux()
	h.RegisterInspectorRoutes(mux)

	form := url.Values{
		"enabled":          {"on"},
		"send_unencrypted": {"on"},
		"xsw_variant":      {"xsw3"},
		"xsw_nameid":       {"evil@example.com"},
		"relay_state":      {"tampered-relay"},
	}
	req := httptest.NewRequest("POST", "/ui/tamper", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /ui/tamper: expected 303, got %d", w.Code)
	}

	got := config.GetConfig()
	if !got.Enabled || !got.SendUnencrypted {
		t.Errorf("expected Enabled and SendUnencrypted to be set, got %+v", got)
	}
	if got.XSWVariant != "xsw3" || got.XSWNameID != "evil@example.com" {
		t.Errorf("XSW settings not saved: %+v", got)
	}
	if got.RelayState != "tampered-relay" {
		t.Errorf("RelayState not saved: %q", got.RelayState)
	}

	// Disabling must switch tampering off without discarding the configuration.
	req = httptest.NewRequest("POST", "/ui/tamper/disable", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	got = config.GetConfig()
	if got.Enabled {
		t.Error("expected tampering to be disabled")
	}
	if !got.SendUnencrypted || got.XSWVariant != "xsw3" {
		t.Errorf("disable discarded configuration: %+v", got)
	}
}
