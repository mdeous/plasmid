package server

import (
	"fmt"
	"slices"

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
