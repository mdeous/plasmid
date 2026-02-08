package server

import (
	"encoding/base64"
	"encoding/xml"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"golang.org/x/crypto/bcrypt"

	internalsml "github.com/mdeous/plasmid/internal/saml"
	"github.com/mdeous/plasmid/pkg/utils"
)

type testEnv struct {
	plasmid *Plasmid
	handler http.Handler
	sp      saml.ServiceProvider
	store   *samlidp.MemoryStore
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	idpKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate IDP key: %v", err)
	}
	idpCert, err := utils.GenerateCertificate(idpKey, "Test IDP", "US", "CA", "LA", "", "", 1)
	if err != nil {
		t.Fatalf("generate IDP cert: %v", err)
	}

	spKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate SP key: %v", err)
	}
	spCert, err := utils.GenerateCertificate(spKey, "Test SP", "US", "CA", "LA", "", "", 1)
	if err != nil {
		t.Fatalf("generate SP cert: %v", err)
	}

	store := &samlidp.MemoryStore{}

	password := "testpass"
	hashedPassword, err := bcryptHash(password)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	user := samlidp.User{
		Name:           "testuser",
		HashedPassword: hashedPassword,
		Email:          "testuser@example.com",
		CommonName:     "Test User",
		Surname:        "User",
		GivenName:      "Test",
	}
	if err := store.Put("/users/testuser", &user); err != nil {
		t.Fatalf("store user: %v", err)
	}

	spMetadataURL, _ := url.Parse("https://sp.example.com/saml2/metadata")
	spAcsURL, _ := url.Parse("https://sp.example.com/saml2/acs")
	sp := saml.ServiceProvider{
		Key:         spKey,
		Certificate: spCert,
		MetadataURL: *spMetadataURL,
		AcsURL:      *spAcsURL,
		IDPMetadata: &saml.EntityDescriptor{},
	}

	spMeta := sp.Metadata()
	svc := samlidp.Service{
		Name:     "testsp",
		Metadata: *spMeta,
	}
	if err := store.Put("/services/testsp", &svc); err != nil {
		t.Fatalf("store service: %v", err)
	}

	idpURL, _ := url.Parse("https://idp.example.com")
	log := slog.Default()

	p, err := New("localhost", 0, idpURL, idpKey, idpCert, store, log)
	if err != nil {
		t.Fatalf("create plasmid: %v", err)
	}

	sp.IDPMetadata = p.IDP.IDP.Metadata()

	inspector := internalsml.NewInspector(100)
	tamperConfig := internalsml.NewTamperConfig()
	p.IDP.IDP.AssertionMaker = internalsml.TamperableAssertionMaker{Config: tamperConfig}

	p.Mux.HandleFunc("POST /login", p.handleLogin)
	idpHandler := internalsml.InterceptMiddleware(inspector, tamperConfig, log, p.IDP)
	p.Mux.Handle("/", idpHandler)

	return &testEnv{
		plasmid: p,
		handler: p.Mux,
		sp:      sp,
		store:   store,
	}
}

func bcryptHash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func extractFormValue(body, name string) string {
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `"\s+value="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		re2 := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `"\s+value='([^']*)'`)
		m = re2.FindStringSubmatch(body)
	}
	if len(m) < 2 {
		return ""
	}
	return html.UnescapeString(m[1])
}

func extractFormAction(body string) string {
	re := regexp.MustCompile(`action="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func cookiesForURL(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSPInitiatedFlow(t *testing.T) {
	env := newTestEnv(t)

	// Step 1: SP creates AuthnRequest redirect URL
	authnURL, err := env.sp.MakeRedirectAuthenticationRequest("relaystate")
	if err != nil {
		t.Fatalf("MakeRedirectAuthenticationRequest: %v", err)
	}

	// Step 2: GET the SSO URL — should return login form
	req := httptest.NewRequest("GET", authnURL.String(), nil)
	req.URL.Scheme = "https"
	req.URL.Host = "idp.example.com"
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("SSO GET: expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	samlRequest := extractFormValue(body, "SAMLRequest")
	if samlRequest == "" {
		t.Fatal("login form missing SAMLRequest hidden field")
	}
	relayState := extractFormValue(body, "RelayState")

	// Step 3: POST /login with credentials + SAMLRequest + RelayState
	form := url.Values{
		"user":        {"testuser"},
		"password":    {"testpass"},
		"SAMLRequest": {samlRequest},
		"RelayState":  {relayState},
	}
	req = httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /login: expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/sso?SAMLRequest=") {
		t.Fatalf("POST /login: expected redirect to /sso?SAMLRequest=..., got %q", location)
	}
	if !strings.Contains(location, "RelayState=") {
		t.Fatalf("POST /login: redirect missing RelayState, got %q", location)
	}
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	// Step 4: Follow the redirect to /sso with session cookie.
	// The SAMLRequest in the redirect URL is in POST-binding format
	// (plain base64 of raw XML), so we POST it to /sso as the SAML
	// library's GET handler expects deflate+base64 (redirect binding).
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	ssoForm := url.Values{
		"SAMLRequest": {redirectURL.Query().Get("SAMLRequest")},
		"RelayState":  {redirectURL.Query().Get("RelayState")},
	}
	req = httptest.NewRequest("POST", "https://idp.example.com/sso", strings.NewReader(ssoForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /sso: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body = w.Body.String()
	if !strings.Contains(body, `name="SAMLResponse"`) {
		t.Fatal("SSO response missing SAMLResponse form field")
	}
	action := extractFormAction(body)
	if action != "https://sp.example.com/saml2/acs" {
		t.Fatalf("SSO response form action: expected SP ACS URL, got %q", action)
	}

	// Step 5: Extract and decode SAMLResponse
	samlResponse := extractFormValue(body, "SAMLResponse")
	if samlResponse == "" {
		t.Fatal("SSO response missing SAMLResponse value")
	}
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	var response saml.Response
	if err := xml.Unmarshal(decoded, &response); err != nil {
		t.Fatalf("parse SAMLResponse XML: %v", err)
	}
	if response.Destination != "https://sp.example.com/saml2/acs" {
		t.Errorf("Response Destination: expected SP ACS URL, got %q", response.Destination)
	}
	// The assertion is encrypted because the SP metadata includes an
	// encryption certificate. Verify EncryptedAssertion is present.
	if response.Assertion == nil && response.EncryptedAssertion == nil {
		t.Fatal("SAMLResponse missing both Assertion and EncryptedAssertion")
	}
}

func TestSPInitiatedFlow_InvalidPassword(t *testing.T) {
	env := newTestEnv(t)

	authnURL, err := env.sp.MakeRedirectAuthenticationRequest("relaystate")
	if err != nil {
		t.Fatalf("MakeRedirectAuthenticationRequest: %v", err)
	}

	req := httptest.NewRequest("GET", authnURL.String(), nil)
	req.URL.Scheme = "https"
	req.URL.Host = "idp.example.com"
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	samlRequest := extractFormValue(w.Body.String(), "SAMLRequest")
	relayState := extractFormValue(w.Body.String(), "RelayState")

	form := url.Values{
		"user":        {"testuser"},
		"password":    {"wrongpassword"},
		"SAMLRequest": {samlRequest},
		"RelayState":  {relayState},
	}
	req = httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	// samlidp re-renders login form (delegates to upstream)
	body := w.Body.String()
	if !strings.Contains(body, "user") || !strings.Contains(body, "password") {
		t.Fatal("expected login form to be re-rendered on invalid password")
	}
}

func TestIDPInitiatedFlow(t *testing.T) {
	env := newTestEnv(t)

	shortcut := samlidp.Shortcut{
		Name:              "testshortcut",
		ServiceProviderID: "https://sp.example.com/saml2/metadata",
	}
	if err := env.store.Put("/shortcuts/testshortcut", &shortcut); err != nil {
		t.Fatalf("store shortcut: %v", err)
	}

	// Step 1: GET /login/testshortcut — should show login form
	req := httptest.NewRequest("GET", "https://idp.example.com/login/testshortcut", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/testshortcut: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "user") || !strings.Contains(body, "password") {
		t.Fatal("IDP-initiated login page missing form fields")
	}

	// Step 2: POST /login with Referer pointing to the shortcut URL
	form := url.Values{
		"user":     {"testuser"},
		"password": {"testpass"},
	}
	req = httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/testshortcut")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /login IDP-initiated: expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if location != "/login/testshortcut" {
		t.Fatalf("POST /login IDP-initiated: expected redirect to /login/testshortcut, got %q", location)
	}
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login IDP-initiated: no session cookie set")
	}

	// Step 3: GET /login/testshortcut with session cookie
	req = httptest.NewRequest("GET", "https://idp.example.com/login/testshortcut", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/testshortcut with session: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body = w.Body.String()
	if !strings.Contains(body, `name="SAMLResponse"`) {
		t.Fatal("IDP-initiated response missing SAMLResponse form field")
	}
}

func TestHandleLogin_NoCredentials(t *testing.T) {
	env := newTestEnv(t)

	form := url.Values{
		"user":     {""},
		"password": {""},
	}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	// delegates to samlidp which renders a login form
	body := w.Body.String()
	if !strings.Contains(body, "user") || !strings.Contains(body, "password") {
		t.Fatal("expected login form when no credentials provided")
	}
}

func TestHandleLogin_FallbackRedirect(t *testing.T) {
	env := newTestEnv(t)

	// Valid auth, no SAMLRequest, no Referer → redirect to /ui/
	form := url.Values{
		"user":     {"testuser"},
		"password": {"testpass"},
	}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("fallback redirect: expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if location != "/ui/" {
		t.Fatalf("fallback redirect: expected /ui/, got %q", location)
	}
}

func TestHandleLogin_UserNotFound(t *testing.T) {
	env := newTestEnv(t)

	form := url.Values{
		"user":     {"nonexistent"},
		"password": {"testpass"},
	}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	// delegates to samlidp which renders a login form
	body := w.Body.String()
	if !strings.Contains(body, "user") || !strings.Contains(body, "password") {
		t.Fatal("expected login form for non-existent user")
	}
}

func TestMetadataEndpoint(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest("GET", "https://idp.example.com/metadata", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /metadata: expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(body), &ed); err != nil {
		t.Fatalf("parse metadata XML: %v", err)
	}
	if ed.EntityID == "" {
		t.Fatal("metadata missing EntityID")
	}
}
