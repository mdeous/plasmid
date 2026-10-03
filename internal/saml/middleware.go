package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/beevik/etree"
	crewsaml "github.com/crewjam/saml"
)

var (
	samlResponseRe = regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`)
	relayStateRe   = regexp.MustCompile(`name="RelayState"\s+value="([^"]*)"`)
	formActionRe   = regexp.MustCompile(`action="([^"]+)"`)
)

type responseCapture struct {
	http.ResponseWriter
	body       *bytes.Buffer
	bufferOnly bool
	statusCode int
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)
	if rc.bufferOnly {
		return len(b), nil
	}
	return rc.ResponseWriter.Write(b)
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	if !rc.bufferOnly {
		rc.ResponseWriter.WriteHeader(code)
	}
}

func InterceptMiddleware(inspector *Inspector, tamperConfig *TamperConfig, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureInbound(inspector, logger, r)

		if tamperConfig != nil {
			tamperConfig.ResetModifications()
		}

		// The response has to be held back whenever we intend to rewrite it,
		// because the SAML library streams the POST-binding form straight out.
		needsRewrite := tamperConfig != nil && tamperConfig.NeedsResponseRewrite()
		capture := &responseCapture{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
			bufferOnly:     needsRewrite,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(capture, r)

		body := capture.body.Bytes()
		if needsRewrite {
			body = rewriteAndSend(w, capture, tamperConfig, logger)
		}
		captureOutbound(inspector, tamperConfig, logger, r, body)
	})
}

func rewriteAndSend(w http.ResponseWriter, capture *responseCapture, tamperConfig *TamperConfig, logger *slog.Logger) []byte {
	body := capture.body.Bytes()
	if tamperConfig.NeedsPostSignTransform() {
		body = transformResponseBody(body, tamperConfig, logger)
	}
	body = tamperRelayState(body, tamperConfig, logger)

	if capture.statusCode != 0 {
		w.WriteHeader(capture.statusCode)
	}
	w.Write(body)
	return body
}

func transformResponseBody(body []byte, tamperConfig *TamperConfig, logger *slog.Logger) []byte {
	matches := samlResponseRe.FindSubmatchIndex(body)
	if matches == nil || len(matches) < 4 {
		return body
	}

	samlB64 := html.UnescapeString(string(body[matches[2]:matches[3]]))
	transformed, mods, err := TransformSAMLResponse(samlB64, tamperConfig, logger)
	if err != nil {
		logger.Error("post-sign transform failed", "error", err)
		return body
	}

	for _, mod := range mods {
		tamperConfig.RecordModification(mod)
	}

	var result []byte
	result = append(result, body[:matches[2]]...)
	result = append(result, []byte(transformed)...)
	result = append(result, body[matches[3]:]...)
	return result
}

// tamperRelayState rewrites the RelayState of the outgoing POST-binding form.
// RelayState is not part of the SAML XML and is not covered by any signature,
// so the value the SP receives is simply whatever sits in this form field.
// Rewriting it here rather than on the way in covers both flows at once: for
// SP-initiated logins the library copies it from the request, while for
// IdP-initiated logins it comes from the stored shortcut and never touches the
// request at all.
func tamperRelayState(body []byte, tamperConfig *TamperConfig, logger *slog.Logger) []byte {
	if tamperConfig == nil || !tamperConfig.IsEnabled() {
		return body
	}
	tamperConfig.mu.RLock()
	newRelayState := tamperConfig.RelayState
	tamperConfig.mu.RUnlock()
	if newRelayState == "" {
		return body
	}

	matches := relayStateRe.FindSubmatchIndex(body)
	if matches == nil || len(matches) < 4 {
		// No POST-binding form in this response (a login page, an error), so
		// there is nothing to rewrite.
		logger.Debug("no RelayState field to tamper in response")
		return body
	}

	oldRelayState := html.UnescapeString(string(body[matches[2]:matches[3]]))
	if oldRelayState == newRelayState {
		return body
	}

	var result []byte
	result = append(result, body[:matches[2]]...)
	// The value sits in an HTML attribute; escaping keeps a payload containing
	// quotes from breaking the form, and the browser posts the raw value.
	result = append(result, []byte(html.EscapeString(newRelayState))...)
	result = append(result, body[matches[3]:]...)

	tamperConfig.RecordModification(TamperModification{
		Field:    "RelayState",
		OldValue: oldRelayState,
		NewValue: newRelayState,
	})
	return result
}

func captureInbound(inspector *Inspector, logger *slog.Logger, r *http.Request) {
	var samlRequest string
	if r.Method == http.MethodGet {
		samlRequest = r.URL.Query().Get("SAMLRequest")
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			samlRequest = r.FormValue("SAMLRequest")
		}
	}
	if samlRequest == "" {
		return
	}

	rawXML, err := decodeSAMLRequest(samlRequest)
	if err != nil {
		logger.Debug("failed to decode SAMLRequest", "error", err)
		return
	}

	var authnReq crewsaml.AuthnRequest
	signed := false
	if err := xml.Unmarshal([]byte(rawXML), &authnReq); err != nil {
		logger.Debug("failed to parse SAMLRequest XML", "error", err)
	} else {
		signed = authnReq.Signature != nil
	}

	sp := ""
	if authnReq.Issuer != nil {
		sp = authnReq.Issuer.Value
	}

	exchange := SAMLExchange{
		Direction:       "Request",
		Endpoint:        r.URL.Path,
		RelayState:      r.FormValue("RelayState"),
		RemoteAddr:      r.RemoteAddr,
		RawXML:          formatXML(rawXML),
		Signed:          signed,
		ServiceProvider: sp,
	}
	inspector.Record(exchange)
}

func captureOutbound(inspector *Inspector, tamperConfig *TamperConfig, logger *slog.Logger, r *http.Request, body []byte) {
	matches := samlResponseRe.FindSubmatch(body)
	if len(matches) < 2 {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(html.UnescapeString(string(matches[1])))
	if err != nil {
		logger.Debug("failed to base64 decode SAMLResponse", "error", err)
		return
	}

	rawXML := string(decoded)
	var response crewsaml.Response
	signed := false
	assertionSigned := false
	nameID := ""
	sp := ""
	var attrs []Attribute

	if err := xml.Unmarshal(decoded, &response); err != nil {
		logger.Debug("failed to parse SAMLResponse XML", "error", err)
	} else {
		signed = response.Signature != nil
		sp = response.Destination
		if response.EncryptedAssertion == nil && response.Assertion != nil {
			assertion := response.Assertion
			assertionSigned = assertion.Signature != nil
			if assertionSigned {
				signed = true
			}
			if assertion.Subject != nil && assertion.Subject.NameID != nil {
				nameID = assertion.Subject.NameID.Value
			}
			for _, stmt := range assertion.AttributeStatements {
				for _, a := range stmt.Attributes {
					var values []string
					for _, v := range a.Values {
						values = append(values, v.Value)
					}
					name := a.Name
					if a.FriendlyName != "" {
						name = a.FriendlyName
					}
					attrs = append(attrs, Attribute{
						Name:   name,
						Values: values,
					})
				}
			}
		}
	}

	var mods []TamperModification
	tampered := false
	if tamperConfig != nil {
		mods = tamperConfig.ConsumeModifications()
		tampered = len(mods) > 0
	}

	acsEndpoint := ""
	if actionMatch := formActionRe.FindSubmatch(body); len(actionMatch) >= 2 {
		acsEndpoint = html.UnescapeString(string(actionMatch[1]))
	}

	rawBase64 := ""
	if samlMatch := samlResponseRe.FindSubmatch(body); len(samlMatch) >= 2 {
		rawBase64 = html.UnescapeString(string(samlMatch[1]))
	}

	// Prefer the RelayState from the outgoing form: it reflects what the SP
	// actually receives, including overrides and IdP-initiated flows where the
	// request carries no RelayState at all.
	relayState := r.FormValue("RelayState")
	if relayMatch := relayStateRe.FindSubmatch(body); len(relayMatch) >= 2 {
		relayState = html.UnescapeString(string(relayMatch[1]))
	}

	exchange := SAMLExchange{
		Direction:       "Response",
		Endpoint:        r.URL.Path,
		ServiceProvider: sp,
		NameID:          nameID,
		RelayState:      relayState,
		RemoteAddr:      r.RemoteAddr,
		RawXML:          formatXML(rawXML),
		Signed:          signed,
		AssertionSigned: assertionSigned,
		Tampered:        tampered,
		Modifications:   mods,
		Attributes:      attrs,
		ACSEndpoint:     acsEndpoint,
		RawBase64:       rawBase64,
	}
	inspector.Record(exchange)
}

// formatXML indents a SAML document for the inspector's raw view.
//
// This goes through etree rather than an encoding/xml decoder-to-encoder round
// trip. That round trip reported every namespace declaration both as the
// element's resolved namespace and as a plain attribute, so the encoder emitted
// each one twice and mangled the second copy into an "_xmlns:" pseudo-prefix.
// The result was still only a display artifact, since the bytes on the wire
// come from the library, but it made the pane unreadable.
//
// A document etree cannot parse is returned unchanged, which is what the parser
// differential modes want anyway: their payloads are deliberately malformed and
// are worth seeing exactly as they went out.
func formatXML(raw string) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		return raw
	}
	doc.Indent(2)
	formatted, err := doc.WriteToString()
	if err != nil {
		return raw
	}
	return formatted
}

func decodeSAMLRequest(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()
	inflated, err := io.ReadAll(reader)
	if err != nil {
		if strings.Contains(err.Error(), "flate") {
			return string(raw), nil
		}
		return "", err
	}
	return string(inflated), nil
}
