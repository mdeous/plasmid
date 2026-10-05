package web

import (
	"strings"
	"testing"
)

// The inspector's raw view used to emit every namespace declaration twice, once
// as the element's resolved namespace and once as a leftover attribute that got
// mangled into an "_xmlns:" pseudo-prefix. The capture path was fixed first and
// this one was left behind, which is why the pane stayed broken while the
// assertion in internal/saml kept passing.
func TestPrettyXMLKeepsNamespaceDeclarationsIntact(t *testing.T) {
	raw := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1">` +
		`<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`</samlp:Response>`

	got := prettyXML(raw)

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
	if !strings.HasPrefix(got, "<samlp:Response") {
		t.Errorf("the element prefix was resolved away into a default namespace:\n%s", got)
	}
}

// A default namespace used to come back twice over, which is not well-formed at
// all: Python's ElementTree rejects it outright as a duplicate attribute.
func TestPrettyXMLDoesNotDuplicateDefaultNamespace(t *testing.T) {
	raw := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1">` +
		`<Status/></Response>`

	got := prettyXML(raw)

	if n := strings.Count(got, `xmlns="urn:oasis:names:tc:SAML:2.0:protocol"`); n != 1 {
		t.Errorf("expected one default declaration, got %d:\n%s", n, got)
	}
}

// A malformed payload is shown exactly as it went out rather than being dropped
// or half-repaired, which is what the parser differential modes need.
func TestPrettyXMLPassesThroughUnparseableInput(t *testing.T) {
	raw := `<samlp:Response><unclosed>`

	if got := prettyXML(raw); got != raw {
		t.Errorf("expected unparseable input to be returned unchanged, got: %s", got)
	}
}

func TestPrettyXMLPassesThroughEmptyInput(t *testing.T) {
	for _, raw := range []string{"", "   \n"} {
		if got := prettyXML(raw); got != raw {
			t.Errorf("prettyXML(%q) = %q, want it unchanged", raw, got)
		}
	}
}

// Comment injection splits a NameID with a comment, and etree indents before
// every non-text child, a comment included — so indenting would move whitespace
// inside the subject value and the pane would show a different NameID than any
// parser reads. A mixed-content document is shown verbatim instead.
func TestPrettyXMLLeavesCommentInjectionAlone(t *testing.T) {
	raw := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">` +
		`<saml:Assertion ID="_a1"><saml:Subject>` +
		`<saml:NameID>admin@evil.example<!---->.corp.example</saml:NameID>` +
		`</saml:Subject></saml:Assertion></samlp:Response>`

	got := prettyXML(raw)

	if got != raw {
		t.Errorf("indenting moved whitespace into the injected NameID:\n got: %q\nwant: %q", got, raw)
	}
}

// An XXE payload names an entity the strict reader will not resolve, so it comes
// back exactly as it went out. A lenient reader passed the reference through as
// text, which the encoder then escaped into a literal "&amp;xxe;".
func TestPrettyXMLPassesThroughEntityReferences(t *testing.T) {
	raw := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:NameID>&xxe;</saml:NameID></samlp:Response>`

	got := prettyXML(raw)

	if got != raw {
		t.Errorf("the entity payload was rewritten:\n got: %q\nwant: %q", got, raw)
	}
	if strings.Contains(got, "&amp;xxe;") {
		t.Error("the entity reference was escaped into literal text")
	}
}

// CDATA framing is the subject of a parsing quirk in its own right, so the pane
// must not quietly turn it into ordinary text.
func TestPrettyXMLPreservesCDATA(t *testing.T) {
	raw := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:NameID><![CDATA[admin@evil.example]]></saml:NameID></samlp:Response>`

	if got := prettyXML(raw); !strings.Contains(got, "<![CDATA[admin@evil.example]]>") {
		t.Errorf("CDATA framing was erased:\n%s", got)
	}
}

// A document that really does carry a duplicate attribute is malformed, and the
// pane has to show that rather than silently keeping one copy.
func TestPrettyXMLPreservesDuplicateAttributes(t *testing.T) {
	raw := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" ID="b"><Status/></Response>`

	got := prettyXML(raw)

	if n := strings.Count(got, "ID="); n != 2 {
		t.Errorf("expected both ID attributes to survive, got %d:\n%s", n, got)
	}
}
