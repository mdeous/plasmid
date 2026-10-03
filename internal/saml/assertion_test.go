package saml

import (
	"testing"

	crewsaml "github.com/crewjam/saml"
)

func addressedAssertion() *crewsaml.Assertion {
	return &crewsaml.Assertion{
		Subject: &crewsaml.Subject{
			SubjectConfirmations: []crewsaml.SubjectConfirmation{
				{SubjectConfirmationData: &crewsaml.SubjectConfirmationData{Address: "127.0.0.1:53384"}},
			},
		},
		AuthnStatements: []crewsaml.AuthnStatement{
			{SubjectLocality: &crewsaml.SubjectLocality{Address: "127.0.0.1:53384"}},
		},
	}
}

// RemoteAddr is "host:port" and behind a tunnel points at the tunnel, so a
// conforming SP rejects the assertion over it. pysaml2 rejects it twice: once
// in valid_address, once in verify_attesting_entity.
func TestNormalizeSubjectAddressDropsBothAddresses(t *testing.T) {
	assertion := addressedAssertion()

	normalizeSubjectAddress(assertion)

	if got := assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Address; got != "" {
		t.Errorf("SubjectConfirmationData Address = %q, want it cleared", got)
	}
	if assertion.AuthnStatements[0].SubjectLocality != nil {
		t.Error("expected SubjectLocality to be dropped entirely, not just blanked")
	}
}

// The library omits both from the XML once they are empty, so the attribute
// really is absent rather than present and empty.
func TestNormalizeSubjectAddressLeavesNoEmptyAttributes(t *testing.T) {
	assertion := addressedAssertion()

	normalizeSubjectAddress(assertion)

	el := assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Element()
	if attr := el.SelectAttr("Address"); attr != nil {
		t.Errorf("Address attribute still serialized as %q", attr.Value)
	}
}

func TestNormalizeSubjectAddressToleratesMissingParts(t *testing.T) {
	normalizeSubjectAddress(nil)
	normalizeSubjectAddress(&crewsaml.Assertion{})
	normalizeSubjectAddress(&crewsaml.Assertion{
		Subject: &crewsaml.Subject{
			SubjectConfirmations: []crewsaml.SubjectConfirmation{{SubjectConfirmationData: nil}},
		},
	})
}
