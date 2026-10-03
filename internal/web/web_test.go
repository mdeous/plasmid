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

func newServiceTestHandler(t *testing.T) (*WebHandler, *samlidp.MemoryStore, *http.ServeMux) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "services-idp"},
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

	store := &samlidp.MemoryStore{}
	baseURL, _ := url.Parse("http://127.0.0.1:8000")
	// handleServiceCreate registers through HandlePutService, so this test needs
	// a real server rather than the nil the other tests get away with.
	idp, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Certificate: cert,
		Store:       store,
	})
	if err != nil {
		t.Fatalf("samlidp.New: %v", err)
	}

	h, err := NewWebHandler(store, idp, slog.Default(), "http://127.0.0.1:8000", cert)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, store, mux
}

func postService(t *testing.T, mux *http.ServeMux, name, metadata string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"name": {name}, "metadata_xml": {metadata}}
	req := httptest.NewRequest("POST", "/ui/services", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// Metadata wrapped in an EntitiesDescriptor used to 400 here; every SP entity it
// describes now becomes its own service.
func TestHandleServiceCreateEntitiesDescriptor(t *testing.T) {
	_, store, mux := newServiceTestHandler(t)

	metadata := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://first.example.com">
    <md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://first.example.com/acs"/></md:SPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://second.example.com">
    <md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://second.example.com/acs"/></md:SPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	w := postService(t, mux, "dd", metadata)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /ui/services: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if rows := strings.Count(w.Body.String(), "<tr"); rows != 2 {
		t.Errorf("expected 2 rows appended, got %d; body: %s", rows, w.Body.String())
	}

	want := map[string]string{
		"dd":   "https://first.example.com",
		"dd-2": "https://second.example.com",
	}
	for name, entityID := range want {
		var svc samlidp.Service
		if err := store.Get("/services/"+name, &svc); err != nil {
			t.Fatalf("service %q was not stored: %v", name, err)
		}
		if svc.Name != name {
			t.Errorf("service %q: Name field is %q", name, svc.Name)
		}
		if svc.Metadata.EntityID != entityID {
			t.Errorf("service %q: expected entity %q, got %q", name, entityID, svc.Metadata.EntityID)
		}
		if len(svc.Metadata.SPSSODescriptors) != 1 {
			t.Errorf("service %q: SPSSODescriptor did not survive, got %+v", name, svc.Metadata)
		}
	}
}

func TestHandleServiceCreateRejectsContainerWithoutSP(t *testing.T) {
	_, store, mux := newServiceTestHandler(t)

	metadata := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.com">
    <md:IDPSSODescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	w := postService(t, mux, "idponly", metadata)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /ui/services: expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
	names, err := store.List("/services/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected no services registered, got %v", names)
	}
}

// A bare EntityDescriptor is still the common case and must keep working.
func TestHandleServiceCreateBareEntityDescriptor(t *testing.T) {
	_, store, mux := newServiceTestHandler(t)

	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/></SPSSODescriptor>
</EntityDescriptor>`

	w := postService(t, mux, "sp", metadata)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /ui/services: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var svc samlidp.Service
	if err := store.Get("/services/sp", &svc); err != nil {
		t.Fatalf("service was not stored: %v", err)
	}
	if svc.Metadata.EntityID != "https://sp.example.com" {
		t.Errorf("unexpected entity ID %q", svc.Metadata.EntityID)
	}
}

func TestHandleServiceCreateRejectsBadName(t *testing.T) {
	_, store, mux := newServiceTestHandler(t)

	w := postService(t, mux, "a/b", `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com"/>`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /ui/services: expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
	names, err := store.List("/services/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected no services registered, got %v", names)
	}
}

func newShortcutTestHandler(t *testing.T) (*WebHandler, *samlidp.MemoryStore, *http.ServeMux) {
	t.Helper()
	store := &samlidp.MemoryStore{}
	// The shortcut handlers only read the store, so the nil idpServer the other
	// tests use is enough here.
	h, err := NewWebHandler(store, nil, slog.Default(), "http://127.0.0.1:8000", nil)
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, store, mux
}

func seedService(t *testing.T, store *samlidp.MemoryStore, name, entityID string) {
	t.Helper()
	service := samlidp.Service{Name: name, Metadata: saml.EntityDescriptor{EntityID: entityID}}
	if err := store.Put("/services/"+name, &service); err != nil {
		t.Fatalf("seed service: %v", err)
	}
}

func postShortcut(t *testing.T, mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/ui/shortcuts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// The dashboard form has to produce the same three RelayState shapes as
// "client login-add": unset, a fixed value, or the URL suffix.
func TestShortcutCreateRelayStateModes(t *testing.T) {
	const entityID = "https://sp.example.com/metadata"

	tests := []struct {
		name       string
		form       url.Values
		wantRelay  *string
		wantSuffix bool
	}{
		{
			name:       "none",
			form:       url.Values{"name": {"plain"}, "entity_id": {entityID}, "relay_state_mode": {""}},
			wantRelay:  nil,
			wantSuffix: false,
		},
		{
			name:       "fixed",
			form:       url.Values{"name": {"fixed"}, "entity_id": {entityID}, "relay_state_mode": {"fixed"}, "relay_state": {"/dashboard"}},
			wantRelay:  ptr("/dashboard"),
			wantSuffix: false,
		},
		{
			// A blank relay_state must leave the pointer nil, or samlidp would
			// resolve it ahead of the suffix flag and send "".
			name:       "suffix",
			form:       url.Values{"name": {"suffixed"}, "entity_id": {entityID}, "relay_state_mode": {"suffix"}, "relay_state": {""}},
			wantRelay:  nil,
			wantSuffix: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, store, mux := newShortcutTestHandler(t)
			seedService(t, store, "testsp", entityID)

			if w := postShortcut(t, mux, tc.form); w.Code != http.StatusOK {
				t.Fatalf("POST /ui/shortcuts: expected 200, got %d (%s)", w.Code, w.Body.String())
			}

			var got samlidp.Shortcut
			if err := store.Get("/shortcuts/"+tc.form.Get("name"), &got); err != nil {
				t.Fatalf("Get shortcut: %v", err)
			}
			if got.ServiceProviderID != entityID {
				t.Errorf("ServiceProviderID = %q, want %q", got.ServiceProviderID, entityID)
			}
			switch {
			case tc.wantRelay == nil && got.RelayState != nil:
				t.Errorf("RelayState = %q, want nil", *got.RelayState)
			case tc.wantRelay != nil && got.RelayState == nil:
				t.Errorf("RelayState = nil, want %q", *tc.wantRelay)
			case tc.wantRelay != nil && *got.RelayState != *tc.wantRelay:
				t.Errorf("RelayState = %q, want %q", *got.RelayState, *tc.wantRelay)
			}
			if got.URISuffixAsRelayState != tc.wantSuffix {
				t.Errorf("URISuffixAsRelayState = %v, want %v", got.URISuffixAsRelayState, tc.wantSuffix)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestShortcutCreateRejectsBadInput(t *testing.T) {
	const entityID = "https://sp.example.com/metadata"

	tests := []struct {
		name string
		form url.Values
	}{
		{"fixed mode with no value", url.Values{"name": {"a"}, "entity_id": {entityID}, "relay_state_mode": {"fixed"}, "relay_state": {"  "}}},
		{"mode the form never offered", url.Values{"name": {"b"}, "entity_id": {entityID}, "relay_state_mode": {"bogus"}}},
		{"unregistered entity id", url.Values{"name": {"c"}, "entity_id": {"https://typo.example.com/metadata"}}},
		{"reserved name", url.Values{"name": {"sp"}, "entity_id": {entityID}}},
		{"name with a slash", url.Values{"name": {"a/b"}, "entity_id": {entityID}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, store, mux := newShortcutTestHandler(t)
			seedService(t, store, "testsp", entityID)

			if w := postShortcut(t, mux, tc.form); w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d (%s)", w.Code, w.Body.String())
			}
			if names, err := store.List("/shortcuts/"); err == nil && len(names) != 0 {
				t.Errorf("expected no shortcut to be stored, got %v", names)
			}
		})
	}
}

// The page has to offer the registered SPs as options, and name the target of
// every shortcut — including one whose SP is gone, which answers every login
// with a bare 404.
func TestShortcutsPageShowsServicesAndTargets(t *testing.T) {
	const entityID = "https://sp.example.com/metadata"
	_, store, mux := newShortcutTestHandler(t)
	seedService(t, store, "testsp", entityID)

	if err := store.Put("/shortcuts/live", &samlidp.Shortcut{Name: "live", ServiceProviderID: entityID}); err != nil {
		t.Fatalf("Put shortcut: %v", err)
	}
	dangling := samlidp.Shortcut{Name: "dead", ServiceProviderID: "https://gone.example.com/metadata"}
	if err := store.Put("/shortcuts/dead", &dangling); err != nil {
		t.Fatalf("Put shortcut: %v", err)
	}

	req := httptest.NewRequest("GET", "/ui/shortcuts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ui/shortcuts: expected 200, got %d", w.Code)
	}
	body := w.Body.String()

	// renderPage streams, so a template error yields a truncated 200.
	if !strings.Contains(body, "</html>") {
		t.Fatal("response body was truncated, template probably failed mid-render")
	}
	if !strings.Contains(body, `<option value="`+entityID+`">testsp (`+entityID+`)</option>`) {
		t.Error("expected the registered service to appear as a dropdown option")
	}
	if !strings.Contains(body, "unregistered") {
		t.Error("expected the shortcut with no registered SP to be flagged")
	}
}

// With nothing registered the form cannot produce a working shortcut, so it is
// replaced by a pointer to the Services page.
func TestShortcutsPageWithoutServices(t *testing.T) {
	_, _, mux := newShortcutTestHandler(t)
	req := httptest.NewRequest("GET", "/ui/shortcuts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, `name="entity_id"`) {
		t.Error("expected no shortcut form when no service is registered")
	}
	if !strings.Contains(body, "/ui/services") {
		t.Error("expected a link to the Services page")
	}
}

// Renaming must not quietly drop the RelayState the shortcut was created with.
func TestShortcutRenameKeepsRelayState(t *testing.T) {
	const entityID = "https://sp.example.com/metadata"
	_, store, mux := newShortcutTestHandler(t)
	seedService(t, store, "testsp", entityID)

	relay := "/dashboard"
	original := samlidp.Shortcut{Name: "before", ServiceProviderID: entityID, RelayState: &relay}
	if err := store.Put("/shortcuts/before", &original); err != nil {
		t.Fatalf("Put shortcut: %v", err)
	}

	req := httptest.NewRequest("POST", "/ui/shortcuts/before/rename", nil)
	req.Header.Set("HX-Prompt", "after")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rename: expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	var got samlidp.Shortcut
	if err := store.Get("/shortcuts/after", &got); err != nil {
		t.Fatalf("Get renamed shortcut: %v", err)
	}
	if got.RelayState == nil || *got.RelayState != relay {
		t.Errorf("RelayState = %v, want %q", got.RelayState, relay)
	}
	// The row that goes back to the browser has to name the new target too.
	if !strings.Contains(w.Body.String(), "testsp") {
		t.Error("expected the rendered row to name the target service")
	}
}
