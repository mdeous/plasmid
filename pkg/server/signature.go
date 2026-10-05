package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SignatureMethods are the XML signature algorithms plasmid will sign
// assertions and responses with. Only the RSA family is listed: the IdP key is
// RSA, so an ECDSA method would fail when a login signs rather than at startup.
//
// SHA-1 is on the list deliberately. It is what crewjam/saml falls back to when
// no method is set, and what most SPs now reject, so being able to select it on
// purpose is a probe in its own right: does this SP still accept a downgraded
// signature?
var SignatureMethods = []string{
	dsig.RSASHA256SignatureMethod,
	dsig.RSASHA384SignatureMethod,
	dsig.RSASHA512SignatureMethod,
	dsig.RSASHA1SignatureMethod,
}

// validateSignatureMethod rejects an unknown algorithm at startup. Left to the
// library it would surface once per login, from inside the signing path, long
// after the operator could connect it to the value they typed.
func validateSignatureMethod(method string) error {
	if method == "" || slices.Contains(SignatureMethods, method) {
		return nil
	}
	return fmt.Errorf("unsupported signature method %q, expected one of %v", method, SignatureMethods)
}

// signMetadata puts an enveloped XMLDSig signature on the already serialized
// EntityDescriptor. crewjam/saml has no metadata signing of its own:
// IdentityProvider.Metadata() never sets ID and never sets Signature.
//
// The signature is added after serialization rather than through
// saml.EntityDescriptor.Signature, which is an *etree.Element whose children are
// an interface slice encoding/xml cannot marshal.
func signMetadata(doc []byte, key *rsa.PrivateKey, cert *x509.Certificate, method string) ([]byte, error) {
	parsed := etree.NewDocument()
	if err := parsed.ReadFromBytes(doc); err != nil {
		return nil, fmt.Errorf("failed to parse idp metadata for signing: %v", err)
	}
	root := parsed.Root()
	if root == nil {
		return nil, fmt.Errorf("idp metadata has no root element")
	}

	keyPair := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  crypto.PrivateKey(key),
		Leaf:        cert,
	}
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(keyPair))
	// The default context canonicalizes with C14N 1.1. Exclusive c14n with an
	// empty prefix list is what the library signs responses with and what SPs
	// expect, so the metadata signature is built the same way.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(method); err != nil {
		return nil, fmt.Errorf("set metadata signature method: %v", err)
	}

	// ConstructSignature rather than SignEnveloped: the latter signs a copy and
	// appends the signature last, which would then have to be detached and
	// grafted back just to move it.
	sig, err := ctx.ConstructSignature(root, true)
	if err != nil {
		return nil, fmt.Errorf("failed to sign idp metadata: %v", err)
	}

	// EntityDescriptorType's sequence is Signature?, Extensions?, then the role
	// descriptors, so the signature belongs first. Left where goxmldsig puts it
	// the document still verifies, but a schema-validating SP rejects it before
	// it ever checks the signature.
	//
	// Inserted with no whitespace around it on purpose. The digest covers the
	// element as it stood before the signature was attached, and the SP strips
	// the signature with the enveloped-signature transform and canonicalizes
	// what is left, so a text node added next to the signature changes the bytes
	// it recomputes. For the same reason the document must not be re-indented
	// after this point.
	root.InsertChildAt(0, sig)

	signed, err := parsed.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed idp metadata: %v", err)
	}
	return signed, nil
}
