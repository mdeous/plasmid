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

var samlResponseRe = regexp.MustCompile(`name="SAMLResponse"\s+value="([^"]+)"`)

type responseCapture struct {
	http.ResponseWriter
	body *bytes.Buffer
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)
	return rc.ResponseWriter.Write(b)
}

func InterceptMiddleware(inspector *Inspector, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureInbound(inspector, logger, r)

		capture := &responseCapture{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
		}
		next.ServeHTTP(capture, r)

		captureOutbound(inspector, logger, r, capture.body.Bytes())
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

func captureOutbound(inspector *Inspector, logger *slog.Logger, r *http.Request, body []byte) {
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
			if assertion.Signature != nil {
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
					attrs = append(attrs, Attribute{
						Name:   a.Name,
						Values: values,
					})
				}
			}
		}
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
		Attributes:      attrs,
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
