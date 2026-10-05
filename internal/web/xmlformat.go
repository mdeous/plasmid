package web

import (
	"strings"

	"github.com/beevik/etree"
)

// prettyXML indents a captured SAML document for the human-facing pane.
//
// This goes through etree rather than an encoding/xml decoder-to-encoder round
// trip. That round trip reported every namespace declaration twice, once as the
// element's resolved namespace and once as a plain attribute, so the encoder
// emitted both and mangled the second into an "_xmlns:" pseudo-prefix bound to
// the literal string "xmlns". A conformant parser then reads _xmlns:saml as an
// attribute rather than a declaration, which is schema-invalid, and a default
// xmlns came back twice over, which is not well-formed at all. It also dropped
// element prefixes, so the pane stopped matching what the SP received.
//
// The reader is deliberately strict and preserves what a laxer one would tidy
// away: CDATA framing, duplicate attributes, and entity references, all of which
// are the subject of an attack mode rather than noise. A document etree cannot
// parse is returned unchanged, which is what the parser differential modes want:
// their payloads are deliberately malformed and are worth seeing exactly as they
// went out.
//
// Indenting still adds whitespace and re-escapes quotes, so the pane is for
// reading only. Anything that has to verify goes through the verbatim export at
// /ui/inspector/{id}/raw instead.
func prettyXML(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	doc.ReadSettings.PreserveDuplicateAttrs = true
	if err := doc.ReadFromString(raw); err != nil {
		return raw
	}
	// etree indents before every non-CharData child, a comment included, so
	// indenting an element that mixes text with anything else moves the added
	// whitespace inside that text. Comment injection turns on exactly that
	// shape, and the pane would then show a different NameID than any parser
	// reads. Show such a document verbatim instead, the same way an unparseable
	// one is shown.
	if root := doc.Root(); root == nil || hasMixedContent(root) {
		return raw
	}
	doc.Indent(2)
	formatted, err := doc.WriteToString()
	if err != nil {
		return raw
	}
	return formatted
}

// hasMixedContent reports whether any element holds text alongside a child that
// indenting would push onto its own line.
func hasMixedContent(e *etree.Element) bool {
	text, other := false, false
	for _, child := range e.Child {
		if data, ok := child.(*etree.CharData); ok {
			if !data.IsWhitespace() {
				text = true
			}
			continue
		}
		other = true
	}
	if text && other {
		return true
	}
	for _, child := range e.ChildElements() {
		if hasMixedContent(child) {
			return true
		}
	}
	return false
}
