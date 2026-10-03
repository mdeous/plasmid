package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crewjam/saml"
)

func TestStampSessionFillsEmptyFields(t *testing.T) {
	session := &saml.Session{UserEmail: "alice@example.com"}

	stampSession(session, "urn:format")

	if session.NameIDFormat != "urn:format" {
		t.Errorf("NameIDFormat = %q, want %q", session.NameIDFormat, "urn:format")
	}
	if session.EduPersonPrincipalName != "alice@example.com" {
		t.Errorf("EduPersonPrincipalName = %q, want the user's email", session.EduPersonPrincipalName)
	}
}

func TestStampSessionLeavesExistingValues(t *testing.T) {
	session := &saml.Session{
		NameIDFormat:           "urn:already-set",
		EduPersonPrincipalName: "bob@example.com",
		UserEmail:              "alice@example.com",
	}

	stampSession(session, "urn:format")

	if session.NameIDFormat != "urn:already-set" {
		t.Errorf("NameIDFormat was overwritten: %q", session.NameIDFormat)
	}
	if session.EduPersonPrincipalName != "bob@example.com" {
		t.Errorf("EduPersonPrincipalName was overwritten: %q", session.EduPersonPrincipalName)
	}
}

// An empty format leaves crewjam/saml's own default in place, so anything
// embedding this package can opt out of the override.
func TestStampSessionEmptyFormatIsNoOp(t *testing.T) {
	session := &saml.Session{}

	stampSession(session, "")

	if session.NameIDFormat != "" {
		t.Errorf("NameIDFormat = %q, want it left empty", session.NameIDFormat)
	}
}

// A user with no email still produces no eduPersonPrincipalName, which upstream
// tags omitempty, so no empty attribute reaches the SP.
func TestStampSessionSkipsPrincipalNameWithoutEmail(t *testing.T) {
	session := &saml.Session{}

	stampSession(session, "urn:format")

	if session.EduPersonPrincipalName != "" {
		t.Errorf("EduPersonPrincipalName = %q, want empty", session.EduPersonPrincipalName)
	}
}

type fixedSessionProvider struct{ session *saml.Session }

func (f fixedSessionProvider) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return f.session
}

func TestSessionStamperStampsWrappedProvider(t *testing.T) {
	stamper := sessionStamper{
		inner:        fixedSessionProvider{session: &saml.Session{UserEmail: "alice@example.com"}},
		nameIDFormat: "urn:format",
	}

	session := stamper.GetSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/sso", nil), nil)

	if session == nil {
		t.Fatal("expected a session")
	}
	if session.NameIDFormat != "urn:format" {
		t.Errorf("NameIDFormat = %q, want %q", session.NameIDFormat, "urn:format")
	}
}

// GetSession returns nil when the provider has already written its own response
// — usually the login form — and that has to pass straight through.
func TestSessionStamperPassesNilThrough(t *testing.T) {
	stamper := sessionStamper{inner: fixedSessionProvider{}, nameIDFormat: "urn:format"}

	if got := stamper.GetSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/sso", nil), nil); got != nil {
		t.Errorf("expected nil session, got %+v", got)
	}
}
