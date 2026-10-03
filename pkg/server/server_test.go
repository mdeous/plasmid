package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	dsig "github.com/russellhaering/goxmldsig"
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

// testNameIDFormat is what cmd/serve defaults config.NameIDFormat to, so the
// tests exercise the format a real run emits.
const testNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// testSignatureMethod mirrors cmd/serve's default for config.SignatureMethod.
const testSignatureMethod = dsig.RSASHA256SignatureMethod

// newTestEnv builds a wired-up Plasmid. Option tweaks are applied before New,
// so a test can exercise a startup setting rather than poking at the live
// config afterwards.
func newTestEnv(t *testing.T, tweaks ...func(*Options)) *testEnv {
	t.Helper()

	idpKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate IDP key: %v", err)
	}
	idpCert, err := utils.GenerateCertificate(idpKey, "Test IDP", "US", "CA", "LA", "", "", 30)
	if err != nil {
		t.Fatalf("generate IDP cert: %v", err)
	}

	spKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate SP key: %v", err)
	}
	spCert, err := utils.GenerateCertificate(spKey, "Test SP", "US", "CA", "LA", "", "", 30)
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

	// A second SP with no encryption certificate, so its assertions stay in
	// the clear and a test can read the subject straight off the wire.
	plainMetadataURL, _ := url.Parse("https://plain.example.com/saml2/metadata")
	plainAcsURL, _ := url.Parse("https://plain.example.com/saml2/acs")
	plainSP := saml.ServiceProvider{
		Key:         spKey,
		Certificate: spCert,
		MetadataURL: *plainMetadataURL,
		AcsURL:      *plainAcsURL,
		IDPMetadata: &saml.EntityDescriptor{},
	}
	plainMeta := plainSP.Metadata()
	for i := range plainMeta.SPSSODescriptors {
		kept := plainMeta.SPSSODescriptors[i].KeyDescriptors[:0]
		for _, kd := range plainMeta.SPSSODescriptors[i].KeyDescriptors {
			if kd.Use != "encryption" {
				kept = append(kept, kd)
			}
		}
		plainMeta.SPSSODescriptors[i].KeyDescriptors = kept
	}
	if err := store.Put("/services/plainsp", &samlidp.Service{Name: "plainsp", Metadata: *plainMeta}); err != nil {
		t.Fatalf("store plaintext service: %v", err)
	}

	idpURL, _ := url.Parse("https://idp.example.com")
	log := slog.Default()

	opts := Options{
		Host:            "localhost",
		Port:            0,
		AdminHost:       "127.0.0.1",
		AdminPort:       8001,
		BaseUrl:         idpURL,
		Key:             idpKey,
		Certificate:     idpCert,
		Store:           store,
		Logger:          log,
		NameIDFormat:    testNameIDFormat,
		SignatureMethod: testSignatureMethod,
	}
	for _, tweak := range tweaks {
		tweak(&opts)
	}

	p, err := New(opts)
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

// TestAdminSurfaceNotPublic covers what the two-listener split protects: the
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

	for _, path := range []string{"/sso", "/metadata", "/login/testshortcut", "/login/sp/testsp"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:8001"+path, nil)
		w := httptest.NewRecorder()
		env.admin.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on admin listener: got %d, want 404", path, w.Code)
		}
	}
}

// TestSignKeyAttackEndToEnd runs a real SP-initiated login with a signing key
// attack enabled. The unit tests in internal/saml sign a hand-built fixture;
// this one proves the re-signing survives a response the library actually
// produced, namespaces and all.
func TestSignKeyAttackEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:         true,
		SendUnencrypted: true,
		SignKeyMode:     internalsml.SignKeyClone,
	})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))

	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	assertion := doc.Root().FindElement("./Assertion")
	if assertion == nil {
		t.Fatalf("response has no assertion: %s", responseXML)
	}

	certEl := assertion.FindElement(".//X509Certificate")
	if certEl == nil {
		t.Fatalf("assertion signature has no certificate: %s", responseXML)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certEl.Text()), ""))
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	attackCert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	realCert := env.plasmid.IDP.IDP.Certificate
	if attackCert.Equal(realCert) {
		t.Fatal("response still carries the real IdP certificate")
	}
	if attackCert.Subject.String() != realCert.Subject.String() {
		t.Errorf("clone subject %q does not match the IdP's %q", attackCert.Subject, realCert.Subject)
	}

	// The signature has to be valid under the attacker certificate, otherwise
	// the SP rejects it as malformed and the test tells us nothing about
	// whether it checks which certificate signed.
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{attackCert}}
	vctx := dsig.NewDefaultValidationContext(&store)
	vctx.Clock = dsig.NewFakeClockAt(attackCert.NotBefore.Add(time.Hour))
	vctx.IdAttribute = "ID"
	if _, err := vctx.Validate(assertion); err != nil {
		t.Fatalf("re-signed assertion does not verify: %v", err)
	}

	recorded := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "Signing Key" {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("expected the inspector to record the signing key attack")
	}
}

// TestSignKeyAttackSkippedWhenEncrypted mirrors the XSW case: the assertion
// signature is sealed inside EncryptedAssertion, so the attack cannot run and
// the operator has to be told rather than left guessing.
func TestSignKeyAttackSkippedWhenEncrypted(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:     true,
		SignKeyMode: internalsml.SignKeyClone,
	})

	env.ssoLogin(t)

	recorded := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "Signing Key" && mod.NewValue == internalsml.SkippedEncryptedNote {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("expected the inspector to record that the signing key attack was skipped")
	}
}

// TestVoidC14NAttackEndToEnd drives a real SP-initiated login with the void
// canonicalization mode on. The unit tests apply it to a hand-built fixture;
// this one shows it survives a response the library actually produced,
// namespaces and all.
func TestVoidC14NAttackEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:         true,
		SendUnencrypted: true,
		NameID:          "admin@evil.example",
		ParserDiffMode:  internalsml.ParserDiffVoidC14N,
	})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))

	// A relative namespace URI makes libxml2 refuse to canonicalize the whole
	// document. It has to be prefixed: libxml2 warns about a relative URI on a
	// default xmlns, and an SP that checks for parse warnings rejects the
	// response before reaching the signature.
	if !strings.Contains(responseXML, `xmlns:plasmid="1"`) {
		t.Errorf("response carries no relative namespace declaration:\n%s", responseXML)
	}
	if strings.Contains(responseXML, `xmlns="1"`) {
		t.Error("the relative namespace must be prefixed, never a default declaration")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	digests := doc.Root().FindElements("//DigestValue")
	if len(digests) == 0 {
		t.Fatalf("response has no DigestValue: %s", responseXML)
	}
	const emptyStringDigest = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	for _, dv := range digests {
		if dv.Text() != emptyStringDigest {
			t.Errorf("DigestValue = %q, want the empty-string hash", dv.Text())
		}
	}

	sv := doc.Root().FindElement("//SignatureValue")
	if sv == nil {
		t.Fatalf("response has no SignatureValue: %s", responseXML)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sv.Text()), ""))
	if err != nil {
		t.Fatalf("decode SignatureValue: %v", err)
	}
	realCert := env.plasmid.IDP.IDP.Certificate
	pub, ok := realCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("IdP certificate does not carry an RSA key")
	}
	sum := sha256.Sum256(nil)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify over the empty string: %v", err)
	}

	// The certificate stays the IdP's own, so an SP rejecting this is rejecting
	// the canonicalization rather than an untrusted signer.
	certEl := doc.Root().FindElement("//X509Certificate")
	if certEl == nil {
		t.Fatal("response has no certificate in KeyInfo")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certEl.Text()), ""))
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	presented, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if !presented.Equal(realCert) {
		t.Error("void canonicalization must present the real IdP certificate")
	}

	if nameID := doc.Root().FindElement("//NameID"); nameID == nil || nameID.Text() != "admin@evil.example" {
		t.Errorf("NameID override did not reach the response: %v", nameID)
	}

	// Negative control: a verifier that canonicalizes correctly has to reject
	// this, or the mode says nothing about the SP.
	assertion := doc.Root().FindElement("./Assertion")
	if assertion == nil {
		t.Fatalf("response has no assertion: %s", responseXML)
	}
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{realCert}}
	vctx := dsig.NewDefaultValidationContext(&store)
	vctx.IdAttribute = "ID"
	if _, err := vctx.Validate(assertion); err == nil {
		t.Error("a strict verifier accepted the void signature")
	}

	recorded := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "Parser Differential" {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("expected the inspector to record the parser differential attack")
	}
}

// TestVoidC14NSkippedWhenEncrypted mirrors the XSW and signing key cases: the
// forged claim lives inside the assertion, which is unreachable once the
// library has encrypted it.
func TestVoidC14NSkippedWhenEncrypted(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:        true,
		ParserDiffMode: internalsml.ParserDiffVoidC14N,
	})

	env.ssoLogin(t)

	found := false
	for _, exchange := range env.inspector.List() {
		for _, mod := range exchange.Modifications {
			if mod.Field == "Parser Differential" && mod.NewValue == internalsml.SkippedEncryptedNote {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected the skipped-because-encrypted note in the inspector")
	}
}

// TestDumpLiveParserDiffPayload writes the response a real SP-initiated login
// produces, so it can be run against an external validation bench. It is a
// no-op unless PLASMID_DUMP_DIR is set: only a real implementation can say
// whether a payload trips its parser.
func TestDumpLiveParserDiffPayload(t *testing.T) {
	dir := os.Getenv("PLASMID_DUMP_DIR")
	if dir == "" {
		t.Skip("set PLASMID_DUMP_DIR to dump the live payload for the validation bench")
	}
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{
		Enabled:         true,
		SendUnencrypted: true,
		NameID:          "admin@evil.example",
		ParserDiffMode:  internalsml.ParserDiffVoidC14N,
	})

	responseXML := decodeSAMLResponse(t, env.ssoLogin(t))
	path := filepath.Join(dir, "live-void_c14n.xml")
	if err := os.WriteFile(path, []byte(responseXML), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	certPath := filepath.Join(dir, "live-idp-cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: env.plasmid.IDP.IDP.Certificate.Raw,
	})
	if err := os.WriteFile(certPath, pemBytes, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Logf("wrote %s and %s", path, certPath)
	t.Logf("ACS=%s entity=%s", env.sp.AcsURL.String(), env.sp.MetadataURL.String())
}

// GET /login/sp/{name} logs into a registered SP without a stored shortcut.
func TestServiceLoginFlow(t *testing.T) {
	env := newTestEnv(t)

	// Step 1: the login form, with no shortcut in the store.
	req := httptest.NewRequest("GET", "https://idp.example.com/login/sp/testsp", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/testsp: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "user") || !strings.Contains(body, "password") {
		t.Fatal("login page missing form fields")
	}

	// Step 2: the form posts to /login, and handleLogin's Referer fallback has
	// to send the operator back here — the path stays under /login/ for exactly
	// this reason.
	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req = httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/sp/testsp")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /login: expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
	if location := w.Header().Get("Location"); location != "/login/sp/testsp" {
		t.Fatalf("POST /login: expected redirect to /login/sp/testsp, got %q", location)
	}
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	// Step 3: the assertion.
	req = httptest.NewRequest("GET", "https://idp.example.com/login/sp/testsp", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/testsp with session: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `name="SAMLResponse"`) {
		t.Fatal("response missing SAMLResponse form field")
	}
}

func TestServiceLoginUnknownService(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest("GET", "https://idp.example.com/login/sp/nosuchservice", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /login/sp/nosuchservice: expected 404, got %d", w.Code)
	}
}

// The service login route has to sit inside the intercept middleware. Without
// it the response is never buffered, so every post-sign transform and the
// RelayState override are silently skipped while assertion-level tampering
// still applies — a quiet half-working state.
func TestServiceLoginGoesThroughTamperMiddleware(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, RelayState: "tampered-relay"})

	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/sp/testsp")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	req = httptest.NewRequest("GET", "https://idp.example.com/login/sp/testsp", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/testsp: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if got := extractFormValue(body, "RelayState"); got != "tampered-relay" {
		t.Errorf("RelayState = %q, want %q", got, "tampered-relay")
	}
	if len(env.inspector.List()) == 0 {
		t.Error("expected the exchange to be recorded by the inspector")
	}
}

// crewjam/saml reads the NameID format off the session and samlidp never sets
// one, so plasmid stamps it. Without the stamp the subject goes out as
// transient and an SP that identifies users by email address rejects the
// assertion for a reason unrelated to whatever is being tested.
func TestIdPInitiatedAssertionCarriesConfiguredNameIDFormat(t *testing.T) {
	env := newTestEnv(t)

	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/sp/plainsp")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	req = httptest.NewRequest("GET", "https://idp.example.com/login/sp/plainsp", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/plainsp: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	decoded, err := base64.StdEncoding.DecodeString(extractFormValue(w.Body.String(), "SAMLResponse"))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	var response saml.Response
	if err := xml.Unmarshal(decoded, &response); err != nil {
		t.Fatalf("parse SAMLResponse XML: %v", err)
	}
	if response.Assertion == nil || response.Assertion.Subject == nil || response.Assertion.Subject.NameID == nil {
		t.Fatalf("expected a plaintext assertion with a subject, got %+v", response)
	}

	nameID := response.Assertion.Subject.NameID
	if nameID.Format != testNameIDFormat {
		t.Errorf("NameID Format = %q, want %q", nameID.Format, testNameIDFormat)
	}
	if nameID.Value != "testuser@example.com" {
		t.Errorf("NameID = %q, want the user's email", nameID.Value)
	}
	if got := assertionAttribute(response.Assertion, "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"); got != "testuser@example.com" {
		t.Errorf("eduPersonPrincipalName = %q, want the user's email", got)
	}
	// No InResponseTo is what makes the response unsolicited, and is correct
	// here: there was no AuthnRequest to respond to.
	if response.InResponseTo != "" {
		t.Errorf("InResponseTo = %q, want empty for an IdP-initiated response", response.InResponseTo)
	}
}

// The served descriptor has to agree with the assertions. crewjam/saml
// hardcodes transient in the metadata it builds, which would otherwise tell an
// SP one thing and then send it another.
func TestMetadataAdvertisesConfiguredNameIDFormat(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest("GET", "https://idp.example.com/metadata", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metadata: expected 200, got %d", w.Code)
	}

	var descriptor saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &descriptor); err != nil {
		t.Fatalf("parse metadata XML: %v", err)
	}
	if len(descriptor.IDPSSODescriptors) == 0 {
		t.Fatal("metadata has no IDPSSODescriptor")
	}
	formats := descriptor.IDPSSODescriptors[0].NameIDFormats
	if len(formats) != 1 || string(formats[0]) != testNameIDFormat {
		t.Errorf("metadata NameIDFormats = %v, want [%s]", formats, testNameIDFormat)
	}
}

func assertionAttribute(assertion *saml.Assertion, name string) string {
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name == name && len(attr.Values) > 0 {
				return attr.Values[0].Value
			}
		}
	}
	return ""
}

// crewjam/saml signs with RSA-SHA1 when no method is set, and most SPs now
// reject that. The attack paths in internal/saml already re-sign with SHA-256,
// so a SHA-1 baseline would have a clean login rejected while a tampered one
// was accepted.
func TestSignaturesUseConfiguredAlgorithm(t *testing.T) {
	env := newTestEnv(t)

	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/sp/plainsp")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	sessionCookie := cookiesForURL(w.Result().Cookies(), "session")
	if sessionCookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	req = httptest.NewRequest("GET", "https://idp.example.com/login/sp/plainsp", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/plainsp: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	decoded, err := base64.StdEncoding.DecodeString(extractFormValue(w.Body.String(), "SAMLResponse"))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	raw := string(decoded)

	if strings.Contains(raw, dsig.RSASHA1SignatureMethod) {
		t.Error("response still carries an RSA-SHA1 signature")
	}
	if n := strings.Count(raw, testSignatureMethod); n < 1 {
		t.Errorf("expected at least one %s signature, found %d", testSignatureMethod, n)
	}
	// goxmldsig derives the digest from the signature method's hash, so this
	// moves with it rather than being configured separately.
	if strings.Contains(raw, "http://www.w3.org/2000/09/xmldsig#sha1") {
		t.Error("response still carries a SHA-1 digest")
	}
	if !strings.Contains(raw, "http://www.w3.org/2001/04/xmlenc#sha256") {
		t.Error("expected a SHA-256 digest method")
	}
}

// loginToSP runs an IdP-initiated login against a registered service and
// returns the raw response XML.
func loginToSP(t *testing.T, env *testEnv, name string) string {
	t.Helper()

	form := url.Values{"user": {"testuser"}, "password": {"testpass"}}
	req := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://idp.example.com/login/sp/"+name)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	cookie := cookiesForURL(w.Result().Cookies(), "session")
	if cookie == nil {
		t.Fatal("POST /login: no session cookie set")
	}

	req = httptest.NewRequest("GET", "https://idp.example.com/login/sp/"+name, nil)
	req.RemoteAddr = "127.0.0.1:53384"
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login/sp/%s: expected 200, got %d; body: %s", name, w.Code, w.Body.String())
	}

	decoded, err := base64.StdEncoding.DecodeString(extractFormValue(w.Body.String(), "SAMLResponse"))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	return string(decoded)
}

// crewjam/saml fills both subject addresses from RemoteAddr, which is
// "host:port" and, behind a tunnel, the tunnel's own loopback end. pysaml2
// rejects such an assertion before it reads any username, so a clean login
// fails for a reason unrelated to what is being tested.
func TestAssertionOmitsSubjectAddressByDefault(t *testing.T) {
	raw := loginToSP(t, newTestEnv(t), "plainsp")

	if strings.Contains(raw, "127.0.0.1") {
		t.Errorf("assertion still carries the client address:\n%s", raw)
	}
	if strings.Contains(raw, "SubjectLocality") {
		t.Error("expected SubjectLocality to be dropped entirely")
	}
	if strings.Contains(raw, "Address=") {
		t.Error("expected no Address attribute anywhere in the assertion")
	}
	// The rest of the subject must survive the normalisation.
	if !strings.Contains(raw, "Recipient=") {
		t.Error("Recipient went missing from SubjectConfirmationData")
	}
	if !strings.Contains(raw, "AuthnStatement") {
		t.Error("AuthnStatement went missing")
	}
	if !strings.Contains(raw, "AuthnContextClassRef") {
		t.Error("AuthnContext went missing with SubjectLocality")
	}
}

// The library's behaviour stays available for an SP that wants the attribute.
func TestAssertionKeepsSubjectAddressWhenRequested(t *testing.T) {
	env := newTestEnv(t)
	env.plasmid.IDP.IDP.AssertionMaker = internalsml.TamperableAssertionMaker{
		Config:                env.tamper,
		IncludeSubjectAddress: true,
	}

	raw := loginToSP(t, env, "plainsp")

	if !strings.Contains(raw, `Address="127.0.0.1:53384"`) {
		t.Errorf("expected the client address to be kept:\n%s", raw)
	}
	if !strings.Contains(raw, "SubjectLocality") {
		t.Error("expected SubjectLocality to be kept")
	}
}

// assertSignaturesValid checks the response signature and the assertion
// signature against the IdP certificate. The assertion is validated from a
// literal substring rather than in place, which is how an SP that pulls the
// assertion out of the response sees it.
func assertSignaturesValid(t *testing.T, env *testEnv, raw string) {
	t.Helper()

	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{env.plasmid.cert}}
	ctx := dsig.NewDefaultValidationContext(&store)

	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if _, err := ctx.Validate(doc.Root()); err != nil {
		t.Errorf("response signature did not validate: %v", err)
	}

	start := strings.Index(raw, "<saml:Assertion")
	end := strings.Index(raw, "</saml:Assertion>")
	if start < 0 || end < 0 {
		t.Fatal("no plaintext assertion to validate")
	}
	assertionDoc := etree.NewDocument()
	if err := assertionDoc.ReadFromString(raw[start : end+len("</saml:Assertion>")]); err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	if _, err := ctx.Validate(assertionDoc.Root()); err != nil {
		t.Errorf("assertion signature did not validate: %v", err)
	}
}

// The startup flag seeds the tamper config rather than bypassing it. An SP that
// publishes an encryption certificate is asking for encryption, so sending
// plaintext is a deviation and has to keep showing up as one.
func TestSendUnencryptedFromStartupSeedsTamperConfig(t *testing.T) {
	env := newTestEnv(t, func(o *Options) { o.SendUnencrypted = true })

	cfg := env.tamper.GetConfig()
	if !cfg.Enabled || !cfg.SendUnencrypted {
		t.Fatalf("expected the tamper config to be seeded, got %+v", cfg)
	}

	// testsp advertises an encryption certificate, unlike plainsp.
	raw := loginToSP(t, env, "testsp")

	if strings.Contains(raw, "EncryptedAssertion") {
		t.Error("expected a plaintext assertion from an SP with an encryption certificate")
	}
	if !strings.Contains(raw, "<saml:Assertion") {
		t.Fatal("no plaintext assertion in the response")
	}
	assertSignaturesValid(t, env, raw)

	exchanges := env.inspector.List()
	if len(exchanges) == 0 {
		t.Fatal("no exchange recorded")
	}
	if !exchanges[0].Tampered {
		t.Error("dropping encryption deviates from the SP's metadata and must be reported")
	}
}

// InResponseTo is applied before the library builds anything, so it lands in
// both the Response and the assertion's SubjectConfirmationData and both stay
// correctly signed. An SP that rejects it must be rejecting the value, not a
// stale digest.
func TestInResponseToOverrideIsSignedIntoBothPlaces(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, InResponseTo: "id-never-issued"})

	raw := loginToSP(t, env, "plainsp")

	var response saml.Response
	if err := xml.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if response.InResponseTo != "id-never-issued" {
		t.Errorf("Response InResponseTo = %q, want the injected value", response.InResponseTo)
	}
	if response.Assertion == nil || response.Assertion.Subject == nil {
		t.Fatal("expected a plaintext assertion with a subject")
	}
	confirmations := response.Assertion.Subject.SubjectConfirmations
	if len(confirmations) == 0 || confirmations[0].SubjectConfirmationData == nil {
		t.Fatal("expected a SubjectConfirmationData")
	}
	if got := confirmations[0].SubjectConfirmationData.InResponseTo; got != "id-never-issued" {
		t.Errorf("SubjectConfirmationData InResponseTo = %q, want the injected value", got)
	}

	assertSignaturesValid(t, env, raw)
}

// On an IdP-initiated login there was no request, so the recorded original is
// spelled out rather than left blank.
func TestInResponseToOverrideRecordedAsModification(t *testing.T) {
	env := newTestEnv(t)
	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, InResponseTo: "id-never-issued"})

	loginToSP(t, env, "plainsp")

	exchanges := env.inspector.List()
	if len(exchanges) == 0 {
		t.Fatal("no exchange recorded")
	}
	var found *internalsml.TamperModification
	for i := range exchanges[0].Modifications {
		if exchanges[0].Modifications[i].Field == "InResponseTo" {
			found = &exchanges[0].Modifications[i]
		}
	}
	if found == nil {
		t.Fatalf("no InResponseTo modification recorded, got %+v", exchanges[0].Modifications)
	}
	if found.OldValue != "(none)" {
		t.Errorf("OldValue = %q, want %q for an unsolicited response", found.OldValue, "(none)")
	}
	if found.NewValue != "id-never-issued" {
		t.Errorf("NewValue = %q, want the injected value", found.NewValue)
	}
}

// Without the override an IdP-initiated response carries no InResponseTo, which
// is what makes it unsolicited.
func TestIdPInitiatedHasNoInResponseToByDefault(t *testing.T) {
	raw := loginToSP(t, newTestEnv(t), "plainsp")

	if strings.Contains(raw, "InResponseTo") {
		t.Errorf("expected no InResponseTo in an unsolicited response:\n%s", raw)
	}
}
