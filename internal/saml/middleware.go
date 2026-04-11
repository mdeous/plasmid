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

	crewsaml "github.com/crewjam/saml"
)

var (
	samlResponseRe = regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`)
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

		tamperRelayState(tamperConfig, r)

		needsPostSign := tamperConfig != nil && tamperConfig.NeedsPostSignTransform()
		capture := &responseCapture{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
			bufferOnly:     needsPostSign,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(capture, r)

		if needsPostSign && capture.bufferOnly {
			body := transformAndSend(w, capture, tamperConfig, logger)
			captureOutbound(inspector, tamperConfig, logger, r, body)
		} else {
			captureOutbound(inspector, tamperConfig, logger, r, capture.body.Bytes())
		}
	})
}

func transformAndSend(w http.ResponseWriter, capture *responseCapture, tamperConfig *TamperConfig, logger *slog.Logger) []byte {
	body := capture.body.Bytes()

	matches := samlResponseRe.FindSubmatchIndex(body)
	if matches == nil || len(matches) < 4 {
		if capture.statusCode != 0 {
			w.WriteHeader(capture.statusCode)
		}
		w.Write(body)
		return body
	}

	samlB64 := html.UnescapeString(string(body[matches[2]:matches[3]]))
	transformed, mods, err := TransformSAMLResponse(samlB64, tamperConfig, logger)
	if err != nil {
		logger.Error("post-sign transform failed", "error", err)
		if capture.statusCode != 0 {
			w.WriteHeader(capture.statusCode)
		}
		w.Write(body)
		return body
	}

	for _, mod := range mods {
		tamperConfig.RecordModification(mod)
	}

	var result []byte
	result = append(result, body[:matches[2]]...)
	result = append(result, []byte(transformed)...)
	result = append(result, body[matches[3]:]...)

	if capture.statusCode != 0 {
		w.WriteHeader(capture.statusCode)
	}
	w.Write(result)
	return result
}

func tamperRelayState(tamperConfig *TamperConfig, r *http.Request) {
	if tamperConfig == nil || !tamperConfig.IsEnabled() {
		return
	}
	tamperConfig.mu.RLock()
	newRelayState := tamperConfig.RelayState
	tamperConfig.mu.RUnlock()
	if newRelayState == "" {
		return
	}

	_ = r.ParseForm()
	oldRelayState := r.Form.Get("RelayState")
	if oldRelayState == "" && r.URL.Query().Get("SAMLRequest") == "" && r.FormValue("SAMLRequest") == "" {
		return
	}
	r.Form.Set("RelayState", newRelayState)
	r.PostForm.Set("RelayState", newRelayState)
	tamperConfig.RecordModification(TamperModification{
		Field:    "RelayState",
		OldValue: oldRelayState,
		NewValue: newRelayState,
	})
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

	exchange := SAMLExchange{
		Direction:       "Response",
		Endpoint:        r.URL.Path,
		ServiceProvider: sp,
		NameID:          nameID,
		RelayState:      r.FormValue("RelayState"),
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

func formatXML(raw string) string {
	var buf bytes.Buffer
	decoder := xml.NewDecoder(strings.NewReader(raw))
	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		if err := encoder.EncodeToken(tok); err != nil {
			return raw
		}
	}
	if err := encoder.Flush(); err != nil {
		return raw
	}
	return buf.String()
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
