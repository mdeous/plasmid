package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
		"sign_key_mode":    {"clone_dn"},
		"parser_diff_mode": {"void_c14n"},
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
	if got.SignKeyMode != "clone_dn" {
		t.Errorf("SignKeyMode not saved: %q", got.SignKeyMode)
	}
	if got.ParserDiffMode != "void_c14n" {
		t.Errorf("ParserDiffMode not saved: %q", got.ParserDiffMode)
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
	// Every configured mode has to survive a disable.
	if got.SignKeyMode != "clone_dn" {
		t.Errorf("disable discarded SignKeyMode: %q", got.SignKeyMode)
	}
	if got.ParserDiffMode != "void_c14n" {
		t.Errorf("disable discarded ParserDiffMode: %q", got.ParserDiffMode)
	}
}

// An unknown signing key mode reaching the config would make every later
// response fail the transform, so the form parser drops it.
func TestTamperSaveRejectsUnknownSignKeyMode(t *testing.T) {
	h, err := NewWebHandler(&samlidp.MemoryStore{}, nil, slog.Default(), "http://127.0.0.1:8000", nil)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	config := internalsml.NewTamperConfig()
	h.SetTamperConfig(config)

	mux := http.NewServeMux()
	h.RegisterInspectorRoutes(mux)

	form := url.Values{"enabled": {"on"}, "sign_key_mode": {"../../etc/passwd"}}
	req := httptest.NewRequest("POST", "/ui/tamper", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if got := config.GetConfig().SignKeyMode; got != "" {
		t.Errorf("unknown mode was accepted: %q", got)
	}
}

// Only validated payloads are offered, so an unvalidated mode posted by hand
// must be dropped just like an unknown one.
func TestTamperSaveRejectsUnofferedParserDiffMode(t *testing.T) {
	h, err := NewWebHandler(&samlidp.MemoryStore{}, nil, slog.Default(), "http://127.0.0.1:8000", nil)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	config := internalsml.NewTamperConfig()
	h.SetTamperConfig(config)
	mux := http.NewServeMux()
	h.RegisterInspectorRoutes(mux)

	for _, mode := range []string{"../../etc/passwd", "ns_confusion", "not_a_mode"} {
		form := url.Values{"enabled": {"on"}, "parser_diff_mode": {mode}}
		req := httptest.NewRequest("POST", "/ui/tamper", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mux.ServeHTTP(httptest.NewRecorder(), req)

		if got := config.GetConfig().ParserDiffMode; got != "" {
			t.Errorf("mode %q was accepted: %q", mode, got)
		}
	}
}

// A mode that signs needs key material to render a diff rather than a transform
// error, so the preview has to carry the live material.
func TestTamperPreviewHasKeyMaterial(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "preview-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	h, err := NewWebHandler(&samlidp.MemoryStore{}, nil, slog.Default(), "http://127.0.0.1:8000", cert)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	config := internalsml.NewTamperConfig()
	config.SetParserDiffer(internalsml.NewParserDiffer(key, cert))
	h.SetTamperConfig(config)
	inspector := internalsml.NewInspector(10)
	h.SetInspector(inspector)

	// void_c14n replaces the signature outright, so the captured response only
	// has to carry an ID and something shaped like a signature.
	captured := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">` +
		`<saml:Issuer>idp</saml:Issuer>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>` +
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
		`<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`
	inspector.Record(internalsml.SAMLExchange{
		Direction: "Response",
		RawBase64: base64.StdEncoding.EncodeToString([]byte(captured)),
	})

	mux := http.NewServeMux()
	h.RegisterInspectorRoutes(mux)

	form := url.Values{
		"enabled":          {"on"},
		"send_unencrypted": {"on"},
		"parser_diff_mode": {"void_c14n"},
		"name_id":          {"admin@evil.example"},
	}
	req := httptest.NewRequest("POST", "/ui/tamper/preview", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "without key material") {
		t.Error("the preview still lacks the attack key material")
	}
	if !strings.Contains(body, "47DEQpj8HBSa") {
		t.Errorf("the preview does not show the void digest; body:\n%s", body)
	}
}
