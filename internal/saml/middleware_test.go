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
