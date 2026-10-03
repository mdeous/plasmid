package utils

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

const (
	entityDescriptor   = "EntityDescriptor"
	entitiesDescriptor = "EntitiesDescriptor"
)

// SPService is one service provider, named and ready to register.
type SPService struct {
	Name       string
	Descriptor saml.EntityDescriptor
	XML        []byte
}

// ValidateEntityName rejects names that would break the row actions generated
// for them: the UI routes match a single path segment, so a name containing a
// slash can never be addressed again once stored.
func ValidateEntityName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if strings.ContainsRune(name, '/') {
		return fmt.Errorf("name must not contain '/'")
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("name must not contain whitespace or control characters")
		}
	}
	return nil
}

// ParseSPServices turns an SP metadata document into the services to register
// for it. The document may be a bare <EntityDescriptor> or an
// <EntitiesDescriptor> wrapping any number of them at any depth; every entity
// carrying an SPSSODescriptor becomes a service, named baseName, baseName-2, …
// in document order.
func ParseSPServices(baseName string, data []byte) ([]SPService, error) {
	baseName = strings.TrimSpace(baseName)
	if err := ValidateEntityName(baseName); err != nil {
		return nil, err
	}

	descriptors, err := parseSPMetadata(data)
	if err != nil {
		return nil, err
	}

	services := make([]SPService, 0, len(descriptors))
	for i, d := range descriptors {
		name := baseName
		if i > 0 {
			name = fmt.Sprintf("%s-%d", baseName, i+1)
		}
		if err := ValidateEntityName(name); err != nil {
			return nil, err
		}
		d.Name = name
		services = append(services, d)
	}
	return services, nil
}

// parseSPMetadata returns one entry per service provider found in the document.
// A bare <EntityDescriptor> is passed through with its original bytes intact;
// only a wrapped document goes through the etree extraction below.
func parseSPMetadata(data []byte) ([]SPService, error) {
	root, err := rootElementName(data)
	if err != nil {
		return nil, err
	}

	switch root {
	case entityDescriptor:
		// Accept any EntityDescriptor, without insisting on an SPSSODescriptor:
		// plasmid is a testing tool and this is the shape it has always taken.
		var md saml.EntityDescriptor
		if err := xml.Unmarshal(data, &md); err != nil {
			return nil, fmt.Errorf("unable to parse SP metadata: %v", err)
		}
		return []SPService{{Descriptor: md, XML: data}}, nil

	case entitiesDescriptor:
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(data); err != nil {
			return nil, fmt.Errorf("unable to parse SP metadata: %v", err)
		}
		var services []SPService
		for _, el := range collectEntityDescriptors(doc.Root()) {
			single, err := standaloneElement(el)
			if err != nil {
				return nil, err
			}
			var md saml.EntityDescriptor
			if err := xml.Unmarshal(single, &md); err != nil {
				return nil, fmt.Errorf("unable to parse SP metadata: %v", err)
			}
			if len(md.SPSSODescriptors) == 0 {
				continue
			}
			services = append(services, SPService{Descriptor: md, XML: single})
		}
		if len(services) == 0 {
			return nil, fmt.Errorf("metadata contains no service provider")
		}
		return services, nil

	default:
		return nil, fmt.Errorf("unexpected root element <%s>, want <%s> or <%s>", root, entityDescriptor, entitiesDescriptor)
	}
}

// rootElementName reports the local name of the document's root element. The
// upstream library detects the wrapped case by string-comparing the error that
// encoding/xml happens to produce; sniffing the first start element does not
// depend on that wording.
func rootElementName(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return "", fmt.Errorf("metadata contains no XML element")
		}
		if err != nil {
			return "", fmt.Errorf("unable to parse SP metadata: %v", err)
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name.Local, nil
		}
	}
}

// collectEntityDescriptors walks the tree depth-first and returns every
// EntityDescriptor element in document order. An EntitiesDescriptor may nest
// further containers (SAML metadata §2.3.1), which the upstream helpers do not
// descend into.
func collectEntityDescriptors(el *etree.Element) []*etree.Element {
	if el == nil {
		return nil
	}
	var found []*etree.Element
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case entityDescriptor:
			found = append(found, child)
		case entitiesDescriptor:
			found = append(found, collectEntityDescriptors(child)...)
		}
	}
	return found
}

// standaloneElement serialises el as a document of its own. Namespace
// declarations are inherited in XML but not copied by a subtree extraction, so
// every xmlns on an ancestor is hoisted onto the copy first; a wrapper that
// declares its prefixes only on the root would otherwise yield a subtree that
// is not well-formed.
func standaloneElement(el *etree.Element) ([]byte, error) {
	clone := el.Copy()

	declared := map[string]bool{}
	for _, attr := range clone.Attr {
		if prefix, ok := namespaceDeclaration(attr); ok {
			declared[prefix] = true
		}
	}
	for ancestor := el.Parent(); ancestor != nil; ancestor = ancestor.Parent() {
		for _, attr := range ancestor.Attr {
			prefix, ok := namespaceDeclaration(attr)
			if !ok || declared[prefix] {
				continue
			}
			clone.CreateAttr(attr.FullKey(), attr.Value)
			declared[prefix] = true
		}
	}

	out, err := etree.NewDocumentWithRoot(clone).WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("unable to extract SP metadata entity: %v", err)
	}
	return out, nil
}

// namespaceDeclaration reports whether attr declares a namespace, and for which
// prefix. The default namespace is reported as the empty prefix.
func namespaceDeclaration(attr etree.Attr) (string, bool) {
	switch {
	case attr.Space == "xmlns":
		return attr.Key, true
	case attr.Space == "" && attr.Key == "xmlns":
		return "", true
	}
	return "", false
}
