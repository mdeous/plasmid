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
	plasmid   *Plasmid
	handler   http.Handler
	admin     http.Handler
	sp        saml.ServiceProvider
	store     *samlidp.MemoryStore
	tamper    *internalsml.TamperConfig
	inspector *internalsml.Inspector
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

	p, err := New(Options{
		Host:        "localhost",
		Port:        0,
		AdminHost:   "127.0.0.1",
		AdminPort:   8001,
		BaseUrl:     idpURL,
		Key:         idpKey,
		Certificate: idpCert,
		Store:       store,
		Logger:      log,
	})
	if err != nil {
		t.Fatalf("create plasmid: %v", err)
	}

	sp.IDPMetadata = p.IDP.IDP.Metadata()

	// Wire through the production route builder so the tests exercise the
	// same public/admin split the server runs with.
	inspector, tamperConfig, err := p.BuildRoutes()
	if err != nil {
		t.Fatalf("build routes: %v", err)
	}

	return &testEnv{
		plasmid:   p,
		handler:   p.PublicMux,
		admin:     p.AdminMux,
		sp:        sp,
		store:     store,
		tamper:    tamperConfig,
		inspector: inspector,
	}
}

// ssoLogin runs a full SP-initiated login the way a browser does and returns
// the body of the final POST-binding page.
func (env *testEnv) ssoLogin(t *testing.T) string {
	t.Helper()

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
	if samlRequest == "" {
		t.Fatal("login form missing SAMLRequest hidden field")
	}
	relayState := extractFormValue(w.Body.String(), "RelayState")

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

	location := w.Header().Get("Location")
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatalf("POST /login: no session cookie set (status %d)", w.Code)
	}

	req = httptest.NewRequest("GET", "https://idp.example.com"+location, nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d; body: %s", location, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func decodeSAMLResponse(t *testing.T, body string) string {
	t.Helper()

	value := extractFormValue(body, "SAMLResponse")
	if value == "" {
		t.Fatal("response missing SAMLResponse form value")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	return string(raw)
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

	// Step 4: Follow the redirect exactly as a browser would, with a plain
	// GET on the Location URL carrying the session cookie. The login form
	// hands us a POST-binding SAMLRequest (plain base64), while GET /sso
	// decodes the redirect binding, so handleLogin has to recompress it.
	req = httptest.NewRequest("GET", "https://idp.example.com"+location, nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d; body: %s", location, w.Code, w.Body.String())
	}
	body = w.Body.String()
	if !strings.Contains(body, `name="SAMLResponse"`) {
		t.Fatal("SSO response missing SAMLResponse form field")
	}
	action := extractFormAction(body)
	if action != "https://sp.example.com/saml2/acs" {
		t.Fatalf("SSO response form action: expected SP ACS URL, got %q", action)
	}
	if got := extractFormValue(body, "RelayState"); got != "relaystate" {
		t.Errorf("SSO response RelayState: expected %q, got %q", "relaystate", got)
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

func TestSSOPostBindingAccepted(t *testing.T) {
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
	if samlRequest == "" {
		t.Fatal("login form missing SAMLRequest hidden field")
	}

	form := url.Values{
		"user":        {"testuser"},
		"password":    {"testpass"},
		"SAMLRequest": {samlRequest},
	}
	req = httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	// POST binding: the SAMLRequest stays plain base64 of the raw XML.
	ssoForm := url.Values{"SAMLRequest": {samlRequest}}
	req = httptest.NewRequest("POST", "https://idp.example.com/sso", strings.NewReader(ssoForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /sso: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `name="SAMLResponse"`) {
		t.Fatal("POST /sso: response missing SAMLResponse form field")
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

	// Valid auth, no SAMLRequest, no Referer → redirect to the dashboard,
	// which lives on the admin listener rather than this one.
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
	if want := "http://127.0.0.1:8001/ui/"; location != want {
		t.Fatalf("fallback redirect: expected %q, got %q", want, location)
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

// The test SP publishes a certificate, so the library encrypts the assertion.
// This is the premise for the tests below: XSW cannot rewrite what it cannot read.
func TestAssertionEncryptedByDefault(t *testing.T) {
	env := newTestEnv(t)

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))
	if !strings.Contains(responseXML, "EncryptedAssertion") {
		t.Fatal("expected an encrypted assertion for an SP that publishes a certificate")
	}
}

func TestSendUnencryptedAssertion(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, SendUnencrypted: true})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))
	if strings.Contains(responseXML, "EncryptedAssertion") {
		t.Error("expected a plaintext assertion when SendUnencrypted is set")
	}
	if !strings.Contains(responseXML, "<saml:Assertion") {
		t.Error("response missing plaintext assertion")
	}
	if !strings.Contains(responseXML, "SignatureValue") {
		t.Error("expected the plaintext assertion to still be signed")
	}
}

func TestXSWSkippedWhenAssertionEncrypted(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:    true,
		XSWVariant: "xsw3",
		XSWNameID:  "evil@example.com",
	})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))
	if strings.Contains(responseXML, "evil@example.com") {
		t.Error("XSW must not apply to an encrypted assertion")
	}

	recorded := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "XSW" && mod.NewValue == internalsml.SkippedEncryptedNote {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("expected the inspector to record that XSW was skipped")
	}
}

func TestXSWAppliesWhenAssertionUnencrypted(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:         true,
		SendUnencrypted: true,
		XSWVariant:      "xsw3",
		XSWNameID:       "evil@example.com",
	})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))
	if !strings.Contains(responseXML, "evil@example.com") {
		t.Fatal("expected XSW to apply once the assertion is sent unencrypted")
	}
}

func TestRelayStateOverrideRedirectBinding(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, RelayState: "tampered-relay"})

	body := env.ssoLogin(t)
	if got := extractFormValue(body, "RelayState"); got != "tampered-relay" {
		t.Errorf("RelayState reaching the SP: expected %q, got %q", "tampered-relay", got)
	}
}

// The IdP-initiated flow takes its RelayState from the stored shortcut, so the
// request never carries one. The override still has to reach the SP.
func TestRelayStateOverrideIDPInitiated(t *testing.T) {
	env := newTestEnv(t)

	shortcut := samlidp.Shortcut{
		Name:              "testshortcut",
		ServiceProviderID: "https://sp.example.com/saml2/metadata",
	}
	if err := env.store.Put("/shortcuts/testshortcut", &shortcut); err != nil {
		t.Fatalf("store shortcut: %v", err)
	}
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, RelayState: "tampered-relay"})

	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/testshortcut")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	req = httptest.NewRequest("GET", "https://idp.example.com/login/testshortcut", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/testshortcut: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="SAMLResponse"`) {
		t.Fatal("IdP-initiated response missing SAMLResponse form field")
	}
	if got := extractFormValue(body, "RelayState"); got != "tampered-relay" {
		t.Errorf("RelayState reaching the SP: expected %q, got %q", "tampered-relay", got)
	}

	recorded := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "RelayState" && mod.NewValue == "tampered-relay" {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("expected the inspector to record the RelayState override")
	}
}

// TestAdminSurfaceNotPublic is the point of the two-listener split: the
// samlidp REST API and the dashboard authenticate nobody, so they must not be
// reachable on the listener an SP (or a tunnel) can talk to.
func TestAdminSurfaceNotPublic(t *testing.T) {
	env := newTestEnv(t)

	adminPaths := []struct {
		method string
		path   string
	}{
		{"GET", "/users/"},
		{"GET", "/users/testuser"},
		{"DELETE", "/users/testuser"},
		{"GET", "/services/"},
		{"GET", "/services/testsp"},
		{"GET", "/sessions/"},
		{"GET", "/shortcuts/"},
		{"GET", "/ui/"},
		{"GET", "/ui/users"},
		{"GET", "/ui/inspector"},
		{"GET", "/ui/tamper"},
		{"GET", "/metadata/cert.pem"},
	}

	for _, tc := range adminPaths {
		req := httptest.NewRequest(tc.method, "https://idp.example.com"+tc.path, nil)
		w := httptest.NewRecorder()
		env.handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: reachable on the public listener (got %d, want 404)", tc.method, tc.path, w.Code)
		}
	}
}

// TestAdminSurfaceServedOnAdminListener is the other half: everything rejected
// above still has to work on the listener the operator uses.
func TestAdminSurfaceServedOnAdminListener(t *testing.T) {
	env := newTestEnv(t)

	adminPaths := []string{
		"/users/",
		"/services/",
		"/sessions/",
		"/shortcuts/",
		"/ui/",
		"/ui/users",
		"/ui/inspector",
		"/ui/tamper",
		"/metadata/cert.pem",
	}

	for _, path := range adminPaths {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8001"+path, nil)
		w := httptest.NewRecorder()
		env.admin.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s on admin listener: got %d, want 200", path, w.Code)
		}
	}
}

// TestSAMLEndpointsNotOnAdminListener keeps the SAML flow off the admin port,
// so a misconfigured SP pointed at the dashboard fails loudly instead of
// half-working.
func TestSAMLEndpointsNotOnAdminListener(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/sso", "/metadata", "/login/testshortcut"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8001"+path, nil)
		w := httptest.NewRecorder()
		env.admin.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on admin listener: got %d, want 404", path, w.Code)
		}
	}
}
