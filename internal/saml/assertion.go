package saml

import crewsaml "github.com/crewjam/saml"

// normalizeSubjectAddress drops the network address crewjam/saml copies out of
// http.Request.RemoteAddr into SubjectConfirmationData/@Address and
// AuthnStatement/SubjectLocality/@Address.
//
// RemoteAddr is "host:port", which is not an address at all, and behind a
// tunnel the host is the tunnel's own loopback end rather than the browser's
// address. Either alone is enough to have a conforming SP reject the
// assertion, and the attribute is optional in SAML 2.0 Core §2.4.1.2, so
// nothing is lost by leaving it out.
//
// pysaml2 rejects it twice over, which is what this was found through:
// valid_address() hands the value to ipaddress.IPv4Address and raises
// NotValid on the port, and verify_attesting_entity() requires the value to
// equal its own remote_addr, so get_subject() raises
// VerificationError("No valid attesting address") before reading any
// username. With the attribute absent both take their "nothing asserted"
// branch and pass.
func normalizeSubjectAddress(assertion *crewsaml.Assertion) {
	if assertion == nil {
		return
	}
	if assertion.Subject != nil {
		for i := range assertion.Subject.SubjectConfirmations {
			if data := assertion.Subject.SubjectConfirmations[i].SubjectConfirmationData; data != nil {
				data.Address = ""
			}
		}
	}
	for i := range assertion.AuthnStatements {
		// Clearing the address would leave a pointless empty element, so drop
		// the whole thing: SubjectLocality carries nothing else plasmid sets.
		assertion.AuthnStatements[i].SubjectLocality = nil
	}
}
