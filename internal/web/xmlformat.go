package web

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// prettyXML reformats the given XML string with indentation. Falls back to the
// original input when parsing fails so that malformed tampered payloads stay
// visible instead of disappearing.
func prettyXML(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	dec := xml.NewDecoder(strings.NewReader(raw))
	dec.Strict = false
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return raw
		}
		if err := enc.EncodeToken(tok); err != nil {
			return raw
		}
	}
	if err := enc.Flush(); err != nil {
		return raw
	}
	return buf.String()
}
