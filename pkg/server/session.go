package server

import (
	"net/http"

	"github.com/crewjam/saml"
)

// stampSession fills in the subject fields samlidp leaves empty.
//
// samlidp sets NameID from the user's email but never sets NameIDFormat, and
// crewjam/saml then falls back to its own hardcoded transient default. An SP
// that identifies users by email address has nothing it can resolve a transient
// subject to, so it rejects the assertion for a reason that has nothing to do
// with whatever is being tested. Datadog is one: with no eduPersonPrincipalName
// present it takes the username from the NameID and requires the emailAddress
// format, and answers anything else with a bare "Assertion could not be
// validated".
//
// eduPersonPrincipalName is filled in for the same reason. SPs that read it
// prefer it over the NameID, several mark it required in their metadata, and
// samlidp never populates it. Upstream tags the field omitempty, so a user with
// no email still produces no attribute.
//
// An empty nameIDFormat means "leave it alone", which keeps the library's own
// behaviour available to anything embedding this package.
func stampSession(session *saml.Session, nameIDFormat string) {
	if session == nil {
		return
	}
	if session.NameIDFormat == "" {
		session.NameIDFormat = nameIDFormat
	}
	if session.EduPersonPrincipalName == "" {
		session.EduPersonPrincipalName = session.UserEmail
	}
}

// sessionStamper applies stampSession to every session the wrapped provider
// hands back. Stamping here rather than only where plasmid creates a session
// also covers the ones samlidp's own login form writes and the ones already
// sitting in the store, neither of which pass through handleLogin.
type sessionStamper struct {
	inner        saml.SessionProvider
	nameIDFormat string
}

func (s sessionStamper) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// A nil session means the provider has already written its own response,
	// usually the login form, and has to be passed straight back.
	session := s.inner.GetSession(w, r, req)
	stampSession(session, s.nameIDFormat)
	return session
}
