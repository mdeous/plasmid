package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// realIDPMaterial stands in for the key and certificate a running plasmid
// signs with.
func realIDPMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{Organization: []string{"Real IdP"}, CommonName: "idp.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

func keyStoreFor(key *rsa.PrivateKey, cert *x509.Certificate) dsig.X509KeyStore {
	return dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	})
}

// signedResponse builds a SAML response whose Assertion carries a real
// enveloped signature, the shape the resigner has to operate on.
func signedResponse(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()

	doc := etree.NewDocument()
	response := doc.CreateElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("ID", "_response1")
	respIssuer := response.CreateElement("saml:Issuer")
	respIssuer.SetText("https://idp.example.com")

	assertion := etree.NewElement("saml:Assertion")
	// Declared on the assertion itself, the way crewjam emits it: the element
	// is signed before it is attached to the response, so it cannot inherit
	// the prefix from a parent.
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", "_assertion1")
	assertion.CreateAttr("Version", "2.0")
	issuer := assertion.CreateElement("saml:Issuer")
	issuer.SetText("https://idp.example.com")
	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.SetText("alice@example.com")

	ctx := dsig.NewDefaultSigningContext(keyStoreFor(key, cert))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	signed, err := ctx.SignEnveloped(assertion)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	response.AddChild(signed)

	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return out
}

func parseResponse(t *testing.T, xmlBytes []byte) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	return doc.Root()
}

func assertionOf(t *testing.T, response *etree.Element) *etree.Element {
	t.Helper()
	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		t.Fatal("result has no assertion")
	}
	return assertion
}

// keyInfoCert returns the certificate advertised inside the signature.
func keyInfoCert(t *testing.T, el *etree.Element) *x509.Certificate {
	t.Helper()
	sig := findSignature(el)
	if sig == nil {
		t.Fatal("element has no signature")
	}
	certEl := findElementRecursive(sig, "ds", "X509Certificate")
	if certEl == nil {
		t.Fatal("signature has no X509Certificate")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certEl.Text()))
	if err != nil {
		t.Fatalf("decode KeyInfo cert: %v", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse KeyInfo cert: %v", err)
	}
	return cert
}

func TestResignerClonesIdentityButNotKey(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	out, desc, err := r.Apply(signedResponse(t, key, cert), SignKeyClone)
	if err != nil {
		t.Fatalf("apply clone: %v", err)
	}
	if !strings.Contains(desc, "clone") {
		t.Errorf("description %q does not mention the clone", desc)
	}

	got := keyInfoCert(t, assertionOf(t, parseResponse(t, out)))

	// Everything an SP might match on by mistake is identical...
	if got.Subject.String() != cert.Subject.String() {
		t.Errorf("subject: got %q, want %q", got.Subject, cert.Subject)
	}
	if got.Issuer.String() != cert.Issuer.String() {
		t.Errorf("issuer: got %q, want %q", got.Issuer, cert.Issuer)
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial: got %v, want %v", got.SerialNumber, cert.SerialNumber)
	}
	// ...but the key, which is the only thing that should count, is not.
	if got.Equal(cert) {
		t.Error("clone carries the real certificate; it must carry a different key")
	}
	if fingerprint(got) == fingerprint(cert) {
		t.Error("clone has the real certificate's fingerprint")
	}
}

func TestResignerValidityWindows(t *testing.T) {
	key, cert := realIDPMaterial(t)
	now := time.Now()

	tests := []struct {
		mode  string
		check func(*testing.T, *x509.Certificate)
	}{
		{SignKeyExpired, func(t *testing.T, c *x509.Certificate) {
			if !c.NotAfter.Before(now) {
				t.Errorf("expired cert NotAfter %v is not in the past", c.NotAfter)
			}
		}},
		{SignKeyNotYetValid, func(t *testing.T, c *x509.Certificate) {
			if !c.NotBefore.After(now) {
				t.Errorf("not-yet-valid cert NotBefore %v is not in the future", c.NotBefore)
			}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			r := NewResigner(cert)
			out, _, err := r.Apply(signedResponse(t, key, cert), tc.mode)
			if err != nil {
				t.Fatalf("apply %s: %v", tc.mode, err)
			}
			tc.check(t, keyInfoCert(t, assertionOf(t, parseResponse(t, out))))
		})
	}
}

func TestResignerUntrustedIsNotTheIdP(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	out, _, err := r.Apply(signedResponse(t, key, cert), SignKeyUntrusted)
	if err != nil {
		t.Fatalf("apply untrusted: %v", err)
	}

	got := keyInfoCert(t, assertionOf(t, parseResponse(t, out)))
	if got.Subject.String() == cert.Subject.String() {
		t.Error("untrusted cert should not reuse the IdP subject")
	}
}

func TestResignerRogueKeyInfoKeepsRealSignature(t *testing.T) {
	key, cert := realIDPMaterial(t)
	original := signedResponse(t, key, cert)
	r := NewResigner(cert)

	out, _, err := r.Apply(original, SignKeyRogueKeyInfo)
	if err != nil {
		t.Fatalf("apply rogue keyinfo: %v", err)
	}

	before := findSignature(assertionOf(t, parseResponse(t, original)))
	after := findSignature(assertionOf(t, parseResponse(t, out)))

	beforeSig := findElement(before, "ds", "SignatureValue").Text()
	afterSig := findElement(after, "ds", "SignatureValue").Text()
	if beforeSig != afterSig {
		t.Error("rogue KeyInfo must leave the real SignatureValue untouched")
	}

	if got := keyInfoCert(t, assertionOf(t, parseResponse(t, out))); got.Equal(cert) {
		t.Error("KeyInfo still advertises the real certificate")
	}
}

func TestResignerStripKeyInfoRemovesItEntirely(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	out, _, err := r.Apply(signedResponse(t, key, cert), SignKeyStripKeyInfo)
	if err != nil {
		t.Fatalf("apply strip keyinfo: %v", err)
	}

	sig := findSignature(assertionOf(t, parseResponse(t, out)))
	if sig == nil {
		t.Fatal("stripping KeyInfo removed the whole signature")
	}
	if findElement(sig, "ds", "KeyInfo") != nil {
		t.Error("KeyInfo is still present")
	}
	if findElement(sig, "ds", "SignatureValue") == nil {
		t.Error("SignatureValue was removed along with KeyInfo")
	}
}

// TestResignedSignatureVerifies is the test that matters: a re-signed
// assertion has to be a cryptographically valid signature under the attacker
// key, otherwise an SP rejects it for the wrong reason and the result of the
// test is meaningless.
func TestResignedSignatureVerifies(t *testing.T) {
	key, cert := realIDPMaterial(t)

	for _, mode := range []string{SignKeyClone, SignKeyUntrusted, SignKeyExpired, SignKeyNotYetValid} {
		t.Run(mode, func(t *testing.T) {
			r := NewResigner(cert)
			out, _, err := r.Apply(signedResponse(t, key, cert), mode)
			if err != nil {
				t.Fatalf("apply %s: %v", mode, err)
			}

			assertion := assertionOf(t, parseResponse(t, out))
			attackCert := keyInfoCert(t, assertion)

			// Validate against the certificate the response itself carries,
			// with the clock pinned inside its window so the expired and
			// not-yet-valid modes are judged on their signature, not on dates.
			store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{attackCert}}
			vctx := dsig.NewDefaultValidationContext(&store)
			vctx.Clock = dsig.NewFakeClockAt(attackCert.NotBefore.Add(time.Hour))
			vctx.IdAttribute = "ID"

			if _, err := vctx.Validate(assertion); err != nil {
				t.Fatalf("re-signed assertion does not verify under its own certificate: %v", err)
			}
		})
	}
}

// TestResignedSignatureFailsUnderRealCert confirms the re-signed assertion is
// actually rejected by an SP that checks against the configured IdP
// certificate — the correct behaviour these modes are probing for.
func TestResignedSignatureFailsUnderRealCert(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	out, _, err := r.Apply(signedResponse(t, key, cert), SignKeyClone)
	if err != nil {
		t.Fatalf("apply clone: %v", err)
	}

	assertion := assertionOf(t, parseResponse(t, out))
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vctx := dsig.NewDefaultValidationContext(&store)
	vctx.Clock = dsig.NewFakeClockAt(cert.NotBefore.Add(time.Hour))
	vctx.IdAttribute = "ID"

	if _, err := vctx.Validate(assertion); err == nil {
		t.Fatal("clone verified against the real IdP certificate; it must not")
	}
}

// TestSignaturePositionFollowsSchema keeps ds:Signature directly after
// saml:Issuer. Appended at the end it still verifies, but a schema-validating
// SP rejects the response before it ever checks the signature.
func TestSignaturePositionFollowsSchema(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	out, _, err := r.Apply(signedResponse(t, key, cert), SignKeyClone)
	if err != nil {
		t.Fatalf("apply clone: %v", err)
	}

	children := assertionOf(t, parseResponse(t, out)).ChildElements()
	if len(children) < 2 {
		t.Fatalf("assertion has %d children, expected Issuer and Signature at least", len(children))
	}
	if children[0].Tag != "Issuer" {
		t.Fatalf("first child is %q, expected Issuer", children[0].Tag)
	}
	if children[1].Tag != "Signature" {
		t.Fatalf("second child is %q, expected Signature", children[1].Tag)
	}
}

func TestResignerRejectsUnknownMode(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	if _, _, err := r.Apply(signedResponse(t, key, cert), "not_a_mode"); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}

// TestResignerReusesMaterial keeps the attacker certificate stable across
// logins, so an operator stepping through modes compares like with like.
func TestResignerReusesMaterial(t *testing.T) {
	key, cert := realIDPMaterial(t)
	r := NewResigner(cert)

	first, _, err := r.Apply(signedResponse(t, key, cert), SignKeyClone)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, _, err := r.Apply(signedResponse(t, key, cert), SignKeyClone)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}

	a := keyInfoCert(t, assertionOf(t, parseResponse(t, first)))
	b := keyInfoCert(t, assertionOf(t, parseResponse(t, second)))
	if !a.Equal(b) {
		t.Error("two runs produced different attacker certificates")
	}
}
