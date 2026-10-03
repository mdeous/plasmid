package server

import (
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestValidateSignatureMethodAcceptsKnownAlgorithms(t *testing.T) {
	for _, method := range SignatureMethods {
		if err := validateSignatureMethod(method); err != nil {
			t.Errorf("validateSignatureMethod(%q) = %v, want nil", method, err)
		}
	}
}

// Empty means "leave the library alone", which is how an embedder keeps
// crewjam/saml's own RSA-SHA1 fallback.
func TestValidateSignatureMethodAcceptsEmpty(t *testing.T) {
	if err := validateSignatureMethod(""); err != nil {
		t.Errorf("validateSignatureMethod(\"\") = %v, want nil", err)
	}
}

func TestValidateSignatureMethodRejectsUnknown(t *testing.T) {
	err := validateSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
	if err == nil {
		t.Fatal("expected an ECDSA method to be rejected: the IdP key is RSA")
	}
	if !strings.Contains(err.Error(), dsig.RSASHA256SignatureMethod) {
		t.Errorf("error should list the accepted methods, got: %v", err)
	}
}

// An unknown algorithm fails at startup rather than once per login from inside
// the signing path.
func TestNewRejectsUnknownSignatureMethod(t *testing.T) {
	opts := Options{SignatureMethod: "rsa-sha256"}

	if _, err := New(opts); err == nil {
		t.Fatal("expected New to reject an unknown signature method")
	}
}
