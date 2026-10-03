package saml

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func enabledConfig(relayState string) *TamperConfig {
	config := NewTamperConfig()
	config.Update(TamperUpdateInput{Enabled: true, RelayState: relayState})
	return config
}

func postBindingForm(relayState string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte("<Response/>"))
	return fmt.Sprintf(
		`<form><input name="SAMLResponse" value="%s" /><input name="RelayState" value="%s" /></form>`,
		encoded, relayState)
}

// RelayState is rewritten in the outgoing form, which is the one place both the
// SP-initiated and IdP-initiated flows pass through.
func TestTamperRelayStateRewritesOutgoingForm(t *testing.T) {
	config := enabledConfig("tampered")

	body := tamperRelayState([]byte(postBindingForm("original")), config, slog.Default())

	if got := string(body); !strings.Contains(got, `name="RelayState" value="tampered"`) {
		t.Errorf("expected the form RelayState to be rewritten, got: %s", got)
	}
	mods := config.ConsumeModifications()
	if len(mods) != 1 || mods[0].Field != "RelayState" {
		t.Fatalf("expected one RelayState modification, got %+v", mods)
	}
	if mods[0].OldValue != "original" || mods[0].NewValue != "tampered" {
		t.Errorf("modification recorded wrong values: %+v", mods[0])
	}
}

// IdP-initiated logins start with an empty RelayState, so the override injects
// a value where the shortcut supplied none.
func TestTamperRelayStateInjectsIntoEmptyField(t *testing.T) {
	config := enabledConfig("tampered")

	body := tamperRelayState([]byte(postBindingForm("")), config, slog.Default())

	if got := string(body); !strings.Contains(got, `name="RelayState" value="tampered"`) {
		t.Errorf("expected RelayState to be injected, got: %s", got)
	}
}

// A payload containing quotes must not break out of the attribute.
func TestTamperRelayStateEscapesValue(t *testing.T) {
	config := enabledConfig(`a"b<c`)

	body := tamperRelayState([]byte(postBindingForm("original")), config, slog.Default())

	if got := string(body); strings.Contains(got, `value="a"b<c"`) {
		t.Errorf("value was not escaped into the attribute: %s", got)
	}
	if got := string(body); !strings.Contains(got, "a&#34;b&lt;c") {
		t.Errorf("expected an escaped value in the form, got: %s", got)
	}
}

func TestTamperRelayStateLeavesResponsesWithoutForm(t *testing.T) {
	config := enabledConfig("tampered")
	original := "<html>login form</html>"

	body := tamperRelayState([]byte(original), config, slog.Default())

	if string(body) != original {
		t.Errorf("expected the body to be untouched, got %q", string(body))
	}
	if mods := config.ConsumeModifications(); len(mods) != 0 {
		t.Errorf("expected no modifications, got %+v", mods)
	}
}

// The RelayState override alone has to trigger response buffering, otherwise
// the form is already on the wire by the time we could rewrite it.
func TestRelayStateOverrideTriggersResponseRewrite(t *testing.T) {
	if !enabledConfig("tampered").NeedsResponseRewrite() {
		t.Error("expected a RelayState override to require a response rewrite")
	}
	if NewTamperConfig().NeedsResponseRewrite() {
		t.Error("expected no rewrite for an empty config")
	}
}

func samlResponseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, postBindingForm("original"))
	})
}

// A flow that records a modification but never emits a SAMLResponse must not
// leave that modification queued for the next exchange.
func TestInterceptMiddlewareDropsStaleModifications(t *testing.T) {
	inspector := NewInspector(10)
	config := enabledConfig("tampered")
	logger := slog.Default()
	target := "/sso?SAMLRequest=abc&RelayState=original"

	noResponse := InterceptMiddleware(inspector, config, logger, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>login form</html>"))
		}))
	noResponse.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target, nil))

	withResponse := InterceptMiddleware(inspector, config, logger, samlResponseHandler())
	withResponse.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target, nil))

	var response *SAMLExchange
	for _, exchange := range inspector.List() {
		if exchange.Direction == "Response" {
			captured := exchange
			response = &captured
			break
		}
	}
	if response == nil {
		t.Fatal("no Response exchange was captured")
	}
	if len(response.Modifications) != 1 {
		t.Fatalf("expected exactly 1 modification for this exchange, got %d: %+v",
			len(response.Modifications), response.Modifications)
	}
	if response.Modifications[0].Field != "RelayState" {
		t.Errorf("expected a RelayState modification, got %q", response.Modifications[0].Field)
	}
}

// The inspector's raw view used to emit every namespace declaration twice, once
// as the element's resolved namespace and once as a leftover attribute that got
// mangled into an "_xmlns:" pseudo-prefix.
func TestFormatXMLKeepsNamespaceDeclarationsIntact(t *testing.T) {
	raw := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1">` +
		`<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`</samlp:Response>`

	got := formatXML(raw)

	if strings.Contains(got, "_xmlns") {
		t.Errorf("namespace declaration was mangled into a pseudo-prefix:\n%s", got)
	}
	if n := strings.Count(got, `xmlns:samlp=`); n != 1 {
		t.Errorf("expected one samlp declaration, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, `xmlns:saml=`); n != 1 {
		t.Errorf("expected one saml declaration, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>") {
		t.Errorf("prefixed element text did not survive indenting:\n%s", got)
	}
}

// A malformed payload is shown exactly as it went out rather than being dropped
// or rewritten, which is what the parser differential modes need.
func TestFormatXMLPassesThroughUnparseableInput(t *testing.T) {
	raw := `<samlp:Response><unclosed>`

	if got := formatXML(raw); got != raw {
		t.Errorf("expected unparseable input to be returned unchanged, got: %s", got)
	}
}

// An encrypted assertion is reported as encrypted rather than as unsigned. The
// library signs the assertion before sealing it, so a plain "No" here read as a
// signing failure and sent an operator chasing a problem that did not exist.
func TestCaptureOutboundMarksEncryptedAssertion(t *testing.T) {
	response := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1"` +
		` Destination="https://sp.example.com/acs">` +
		`<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue/></ds:Signature>` +
		`<saml:EncryptedAssertion><xenc:EncryptedData` +
		` xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>` +
		`</samlp:Response>`
	body := fmt.Sprintf(`<form><input name="SAMLResponse" value="%s" /></form>`,
		base64.StdEncoding.EncodeToString([]byte(response)))

	inspector := NewInspector(10)
	req := httptest.NewRequest(http.MethodGet, "/login/sp/testsp", nil)
	captureOutbound(inspector, nil, slog.Default(), req, []byte(body))

	exchanges := inspector.List()
	if len(exchanges) != 1 {
		t.Fatalf("expected one recorded exchange, got %d", len(exchanges))
	}
	ex := exchanges[0]
	if !ex.AssertionEncrypted {
		t.Error("expected AssertionEncrypted to be set for an EncryptedAssertion")
	}
	if ex.AssertionSigned {
		t.Error("expected AssertionSigned to stay false: the signature is not visible")
	}
	if !ex.Signed {
		t.Error("expected the response signature to still be reported")
	}
}

// A plaintext signed assertion is still reported as signed, not as encrypted.
func TestCaptureOutboundMarksPlaintextAssertionSigned(t *testing.T) {
	response := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1">` +
		`<saml:Assertion ID="id-2">` +
		`<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue/></ds:Signature>` +
		`</saml:Assertion></samlp:Response>`
	body := fmt.Sprintf(`<form><input name="SAMLResponse" value="%s" /></form>`,
		base64.StdEncoding.EncodeToString([]byte(response)))

	inspector := NewInspector(10)
	req := httptest.NewRequest(http.MethodGet, "/login/sp/testsp", nil)
	captureOutbound(inspector, nil, slog.Default(), req, []byte(body))

	ex := inspector.List()[0]
	if ex.AssertionEncrypted {
		t.Error("expected AssertionEncrypted to stay false for a plaintext assertion")
	}
	if !ex.AssertionSigned {
		t.Error("expected AssertionSigned to be set")
	}
	if ex.NameID != "alice@example.com" {
		t.Errorf("expected the NameID to be read, got %q", ex.NameID)
	}
}
