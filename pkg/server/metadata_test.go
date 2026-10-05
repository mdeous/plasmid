package server

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	dsig "github.com/russellhaering/goxmldsig"

	internalsml "github.com/mdeous/plasmid/internal/saml"
	"github.com/mdeous/plasmid/pkg/utils"
)

// parseMetadata round-trips the exported document, which is how an SP reads it.
func parseMetadata(t *testing.T, p *Plasmid) ([]byte, *saml.EntityDescriptor) {
	t.Helper()
	raw, err := p.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return raw, &ed
}

// Left to crewjam/saml, validUntil lands 48h out regardless of how long the
// signing certificate lives, so an instance pinned to a year-long certificate
// still publishes metadata an SP considers expired two days in.
func TestMetadataValidUntilTracksCertificate(t *testing.T) {
	env := newTestEnv(t)

	_, ed := parseMetadata(t, env.plasmid)

	want := env.plasmid.cert.NotAfter
	if diff := ed.ValidUntil.Sub(want); diff > time.Second || diff < -time.Second {
		t.Errorf("validUntil = %v, want the certificate NotAfter %v (diff %v)", ed.ValidUntil, want, diff)
	}

	// The whole point is that this follows the certificate rather than the
	// library's 48h, so it has to be well clear of 48h.
	if remaining := time.Until(ed.ValidUntil); remaining < 20*24*time.Hour {
		t.Errorf("validUntil %v is only %v out, expected to track the 30-day test certificate", ed.ValidUntil, remaining)
	}
}

// cacheDuration answers a different question from validUntil and is left at the
// library's 48h on purpose, so an SP still re-fetches after a certificate swap.
func TestMetadataCacheDurationUnchanged(t *testing.T) {
	env := newTestEnv(t)

	raw, _ := parseMetadata(t, env.plasmid)

	if !strings.Contains(string(raw), `cacheDuration="PT48H"`) {
		t.Errorf("expected cacheDuration=\"PT48H\" to be left alone, got:\n%s", firstLine(string(raw)))
	}
}

func TestMetadataValidDaysOverride(t *testing.T) {
	// Shorter than the fixture certificate, so the override is distinguishable
	// from the certificate-tracking default.
	const overrideDays = 7
	env := newTestEnv(t, func(o *Options) { o.MetadataValidDays = overrideDays })

	_, ed := parseMetadata(t, env.plasmid)

	// Computed in UTC like the production path: AddDate on a local time can
	// cross a DST boundary and land an hour off exactly n*24h.
	want := saml.TimeNow().AddDate(0, 0, overrideDays)
	if diff := ed.ValidUntil.Sub(want); diff > time.Minute || diff < -time.Minute {
		t.Errorf("validUntil = %v, want ~%v (diff %v)", ed.ValidUntil, want, diff)
	}
	// The override has to win over the certificate, which outlives it.
	if !ed.ValidUntil.Before(env.plasmid.cert.NotAfter) {
		t.Errorf("validUntil %v did not override the certificate NotAfter %v", ed.ValidUntil, env.plasmid.cert.NotAfter)
	}
}

// saml.RelaxedTime formats unconditionally, so a validUntil left at the zero
// time is emitted as 0001-01-01 rather than omitted.
func TestMetadataValidUntilNeverZero(t *testing.T) {
	for name, tweak := range map[string]func(*Options){
		"default":  func(*Options) {},
		"override": func(o *Options) { o.MetadataValidDays = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, tweak)
			raw, ed := parseMetadata(t, env.plasmid)
			if ed.ValidUntil.IsZero() {
				t.Error("validUntil is the zero time")
			}
			if strings.Contains(string(raw), "0001-01-01") {
				t.Errorf("metadata carries a zero timestamp:\n%s", firstLine(string(raw)))
			}
		})
	}
}

// The operator-facing endpoint has to agree with the exported file.
func TestMetadataEndpointCarriesCertificateValidity(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metadata = %d, want 200", rec.Code)
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(rec.Body.Bytes(), &ed); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if diff := ed.ValidUntil.Sub(env.plasmid.cert.NotAfter); diff > time.Second || diff < -time.Second {
		t.Errorf("endpoint validUntil = %v, want the certificate NotAfter %v", ed.ValidUntil, env.plasmid.cert.NotAfter)
	}
}

// A certificate that does not match the key makes every assertion fail
// verification at the SP with nothing naming the cause, so New refuses it.
// Built directly rather than through newTestEnv, which fatals on a New error.
func TestNewRejectsMismatchedKeyPair(t *testing.T) {
	key, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert, err := utils.GenerateCertificate(key, "Test IDP", "US", "CA", "LA", "", "", 30)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	otherKey, err := utils.GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}

	baseUrl, _ := url.Parse("https://idp.example.com")
	opts := Options{
		BaseUrl:     baseUrl,
		Key:         otherKey,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
		Logger:      slog.Default(),
	}

	if _, err := New(opts); err == nil {
		t.Fatal("expected New to reject a certificate that does not match the key")
	} else if !strings.Contains(err.Error(), "public half") {
		t.Errorf("error %q does not explain the key/certificate mismatch", err)
	}

	// The matched pair must still be accepted, so the guard is not just
	// refusing everything.
	opts.Key = key
	if _, err := New(opts); err != nil {
		t.Errorf("New rejected a matched pair: %v", err)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// signedEnv is the test env with metadata signing on, which is opt-in.
func signedEnv(t *testing.T, tweaks ...func(*Options)) *testEnv {
	t.Helper()
	all := append([]func(*Options){func(o *Options) { o.SignMetadata = true }}, tweaks...)
	return newTestEnv(t, all...)
}

// An unsigned EntityDescriptor is valid SAML and is what plasmid has always
// published, so nothing about the document may change until signing is asked for.
func TestMetadataUnsignedByDefault(t *testing.T) {
	env := newTestEnv(t)

	raw, _ := parseMetadata(t, env.plasmid)

	if strings.Contains(string(raw), "Signature") {
		t.Errorf("unsigned metadata carries a signature:\n%s", raw)
	}
	// The ID attribute only exists to be referenced by a signature.
	if strings.Contains(string(raw), " ID=") {
		t.Errorf("unsigned metadata carries an ID attribute:\n%s", firstLine(string(raw)))
	}
}

func TestMetadataSignatureValidates(t *testing.T) {
	env := signedEnv(t)

	raw, err := env.plasmid.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	validateSignature(t, env, string(raw), "metadata")
}

// EntityDescriptorType's sequence is Signature?, Extensions?, then the role
// descriptors. goxmldsig appends the signature last, which still verifies but is
// rejected by a schema-validating SP before it ever checks the signature.
func TestMetadataSignatureIsFirstChild(t *testing.T) {
	env := signedEnv(t)

	root := metadataRoot(t, env.plasmid)

	var first *etree.Element
	for _, child := range root.Child {
		if el, ok := child.(*etree.Element); ok {
			first = el
			break
		}
	}
	if first == nil {
		t.Fatal("metadata has no child elements")
	}
	if first.Tag != "Signature" {
		t.Errorf("first child element is %q, want the signature", first.Tag)
	}
}

// goxmldsig reads the reference URI off the element's ID attribute and silently
// falls back to a whole-document URI="" when there is none.
func TestMetadataSignatureReferencesDescriptorID(t *testing.T) {
	env := signedEnv(t)

	root := metadataRoot(t, env.plasmid)

	id := root.SelectAttrValue("ID", "")
	if id == "" {
		t.Fatal("signed metadata has no ID attribute")
	}
	// xsd:ID cannot start with a digit.
	if !strings.HasPrefix(id, "_") {
		t.Errorf("ID %q does not start with an underscore", id)
	}

	ref := root.FindElement("./Signature/SignedInfo/Reference")
	if ref == nil {
		t.Fatal("no ds:Reference in the metadata signature")
	}
	if got, want := ref.SelectAttrValue("URI", ""), "#"+id; got != want {
		t.Errorf("reference URI = %q, want %q", got, want)
	}
}

// The endpoint, the startup export and the dashboard's copy all go through
// Metadata, and an SP that tracks metadata by ID must not see one document as
// several.
func TestMetadataIDStableAcrossCalls(t *testing.T) {
	env := signedEnv(t)

	first := metadataRoot(t, env.plasmid).SelectAttrValue("ID", "")
	second := metadataRoot(t, env.plasmid).SelectAttrValue("ID", "")
	if first == "" || first != second {
		t.Errorf("metadata ID changed between calls: %q then %q", first, second)
	}

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metadata = %d, want 200", rec.Code)
	}
	served := etree.NewDocument()
	if err := served.ReadFromBytes(rec.Body.Bytes()); err != nil {
		t.Fatalf("parse served metadata: %v", err)
	}
	if got := served.Root().SelectAttrValue("ID", ""); got != first {
		t.Errorf("endpoint ID = %q, want the exported %q", got, first)
	}
	validateSignature(t, env, rec.Body.String(), "served metadata")
}

// An explicit signature_method has to reach the metadata too, so a downgrade
// probe covers the whole published surface.
func TestMetadataSignatureFollowsSignatureMethod(t *testing.T) {
	env := signedEnv(t, func(o *Options) { o.SignatureMethod = dsig.RSASHA512SignatureMethod })

	root := metadataRoot(t, env.plasmid)

	method := root.FindElement("./Signature/SignedInfo/SignatureMethod")
	if method == nil {
		t.Fatal("no ds:SignatureMethod in the metadata signature")
	}
	if got := method.SelectAttrValue("Algorithm", ""); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("signature method = %q, want %q", got, dsig.RSASHA512SignatureMethod)
	}
	validateSignature(t, env, metadataString(t, env.plasmid), "metadata")
}

// An empty signature_method means "leave crewjam/saml's default alone", and the
// library has no metadata signing to leave alone. Falling back to its RSA-SHA1
// response default would have the document rejected for a reason nobody chose.
func TestMetadataSignatureDefaultsToSHA256(t *testing.T) {
	env := signedEnv(t, func(o *Options) { o.SignatureMethod = "" })

	root := metadataRoot(t, env.plasmid)

	method := root.FindElement("./Signature/SignedInfo/SignatureMethod")
	if method == nil {
		t.Fatal("no ds:SignatureMethod in the metadata signature")
	}
	if got := method.SelectAttrValue("Algorithm", ""); got != dsig.RSASHA256SignatureMethod {
		t.Errorf("signature method = %q, want %q", got, dsig.RSASHA256SignatureMethod)
	}
}

// GET /metadata is wrapped in the intercept middleware, which buffers and
// rewrites the whole body whenever the tamper config needs a response rewrite.
// The rewrite is a no-op on metadata, and has to stay one: anything that
// re-serializes the document invalidates the signature.
func TestMetadataSignatureSurvivesTamperMiddleware(t *testing.T) {
	env := signedEnv(t)

	env.tamper.Update(internalsml.TamperUpdateInput{Enabled: true, RelayState: "tampered"})
	if !env.tamper.NeedsResponseRewrite() {
		t.Fatal("tamper config does not need a response rewrite, the middleware would not buffer")
	}

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metadata = %d, want 200", rec.Code)
	}
	validateSignature(t, env, rec.Body.String(), "metadata through the middleware")
}

func metadataString(t *testing.T, p *Plasmid) string {
	t.Helper()
	raw, err := p.Metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	return string(raw)
}

// metadataRoot parses the document as etree rather than through
// saml.EntityDescriptor: its Signature field is an *etree.Element that
// encoding/xml cannot represent, so an unmarshalled struct loses the signature.
func metadataRoot(t *testing.T, p *Plasmid) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(metadataString(t, p)); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}
	root := doc.Root()
	if root == nil {
		t.Fatal("metadata has no root element")
	}
	return root
}
