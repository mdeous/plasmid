package utils

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

func TestValidateEntityName(t *testing.T) {
	valid := []string{"alice", "test-sp", "sp_1", "a.b", "Admin@example.com"}
	for _, name := range valid {
		if err := ValidateEntityName(name); err != nil {
			t.Errorf("ValidateEntityName(%q): unexpected error %v", name, err)
		}
	}

	invalid := []string{"", "a/b", "with space", "tab\there", "new\nline"}
	for _, name := range invalid {
		if err := ValidateEntityName(name); err == nil {
			t.Errorf("ValidateEntityName(%q): expected an error, got nil", name)
		}
	}
}

const bareEntity = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`

// The shape Datadog serves: every prefix is declared on the wrapper only, so
// extracting the entity has to carry those declarations down with it.
const wrappedEntityRootPrefixes = `<ns0:EntitiesDescriptor Name="example" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns1="http://www.w3.org/2000/09/xmldsig#">
  <ns0:EntityDescriptor entityID="https://sp.example.com">
    <ns0:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <ns0:KeyDescriptor use="signing">
        <ns1:KeyInfo><ns1:X509Data><ns1:X509Certificate>QUJD</ns1:X509Certificate></ns1:X509Data></ns1:KeyInfo>
      </ns0:KeyDescriptor>
      <ns0:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
    </ns0:SPSSODescriptor>
  </ns0:EntityDescriptor>
</ns0:EntitiesDescriptor>`

func TestParseSPServicesBareEntity(t *testing.T) {
	services, err := ParseSPServices("sp", []byte(bareEntity))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Name != "sp" {
		t.Errorf("expected name 'sp', got %q", services[0].Name)
	}
	if services[0].Descriptor.EntityID != "https://sp.example.com" {
		t.Errorf("unexpected entity ID %q", services[0].Descriptor.EntityID)
	}
	// An unwrapped document is handed on untouched, so the library sees exactly
	// the bytes it would have seen before.
	if string(services[0].XML) != bareEntity {
		t.Errorf("XML was rewritten:\n%s", services[0].XML)
	}
}

// Guards the namespace hoisting: without it the extracted entity declares no
// prefixes and is not well-formed.
func TestParseSPServicesWrappedCarriesNamespaces(t *testing.T) {
	services, err := ParseSPServices("dd", []byte(wrappedEntityRootPrefixes))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}

	// Re-parse the extracted document the way HandlePutService will.
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(services[0].XML, &md); err != nil {
		t.Fatalf("extracted XML does not re-parse: %v\n%s", err, services[0].XML)
	}
	if len(md.SPSSODescriptors) != 1 {
		t.Fatalf("expected 1 SPSSODescriptor, got %d", len(md.SPSSODescriptors))
	}
	sp := md.SPSSODescriptors[0]
	if len(sp.AssertionConsumerServices) != 1 || sp.AssertionConsumerServices[0].Location != "https://sp.example.com/acs" {
		t.Errorf("ACS did not survive extraction: %+v", sp.AssertionConsumerServices)
	}
	if len(sp.KeyDescriptors) != 1 {
		t.Fatalf("expected 1 KeyDescriptor, got %d", len(sp.KeyDescriptors))
	}
	certs := sp.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates
	if len(certs) != 1 || strings.TrimSpace(certs[0].Data) != "QUJD" {
		t.Errorf("certificate did not survive extraction: %+v", certs)
	}
}

// A signature on the entity is the case a marshal/unmarshal round-trip of
// saml.EntityDescriptor would mangle, since its Signature field is an
// *etree.Element that encoding/xml cannot reproduce.
func TestParseSPServicesSignedEntity(t *testing.T) {
	doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:EntityDescriptor entityID="https://sp.example.com">
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#x"/></ds:SignedInfo><ds:SignatureValue>QUJD</ds:SignatureValue></ds:Signature>
    <md:SPSSODescriptor>
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
    </md:SPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	services, err := ParseSPServices("sp", []byte(doc))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if !strings.Contains(string(services[0].XML), "SignatureValue") {
		t.Errorf("signature was dropped from the extracted entity:\n%s", services[0].XML)
	}
	sp := services[0].Descriptor.SPSSODescriptors
	if len(sp) != 1 || sp[0].AssertionConsumerServices[0].Location != "https://sp.example.com/acs" {
		t.Errorf("ACS did not survive extraction: %+v", sp)
	}
}

// Entities without an SPSSODescriptor are skipped, and the numbering follows
// document order over the ones that are kept.
func TestParseSPServicesMultipleSkipsIDPOnly(t *testing.T) {
	doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://first.example.com">
    <md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://first.example.com/acs"/></md:SPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://idp.example.com">
    <md:IDPSSODescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://second.example.com">
    <md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://second.example.com/acs"/></md:SPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	services, err := ParseSPServices("fed", []byte(doc))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	want := []struct{ name, entity string }{
		{"fed", "https://first.example.com"},
		{"fed-2", "https://second.example.com"},
	}
	for i, w := range want {
		if services[i].Name != w.name {
			t.Errorf("service %d: expected name %q, got %q", i, w.name, services[i].Name)
		}
		if services[i].Descriptor.EntityID != w.entity {
			t.Errorf("service %d: expected entity %q, got %q", i, w.entity, services[i].Descriptor.EntityID)
		}
	}
}

// §2.3.1 lets an EntitiesDescriptor nest further containers; the upstream
// helpers only look one level down.
func TestParseSPServicesNestedContainer(t *testing.T) {
	doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntitiesDescriptor Name="inner">
    <md:EntitiesDescriptor Name="innermost">
      <md:EntityDescriptor entityID="https://deep.example.com">
        <md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://deep.example.com/acs"/></md:SPSSODescriptor>
      </md:EntityDescriptor>
    </md:EntitiesDescriptor>
  </md:EntitiesDescriptor>
</md:EntitiesDescriptor>`

	services, err := ParseSPServices("deep", []byte(doc))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Descriptor.EntityID != "https://deep.example.com" {
		t.Errorf("unexpected entity ID %q", services[0].Descriptor.EntityID)
	}
}

// A prefix declared on an inner container, not the root, still has to reach the
// extracted entity.
func TestParseSPServicesNestedNamespaceDeclaration(t *testing.T) {
	doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntitiesDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <md:EntityDescriptor entityID="https://sp.example.com">
      <md:SPSSODescriptor>
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>QUJD</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>
  </md:EntitiesDescriptor>
</md:EntitiesDescriptor>`

	services, err := ParseSPServices("sp", []byte(doc))
	if err != nil {
		t.Fatalf("ParseSPServices: %v", err)
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(services[0].XML, &md); err != nil {
		t.Fatalf("extracted XML does not re-parse: %v\n%s", err, services[0].XML)
	}
	certs := md.SPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates
	if len(certs) != 1 || strings.TrimSpace(certs[0].Data) != "QUJD" {
		t.Errorf("certificate did not survive extraction: %+v", certs)
	}
}

func TestParseSPServicesErrors(t *testing.T) {
	idpOnly := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.com">
    <md:IDPSSODescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

	tests := []struct {
		name string
		base string
		doc  string
		want string
	}{
		{"no service provider", "sp", idpOnly, "no service provider"},
		{"wrong root element", "sp", `<Something xmlns="urn:x"/>`, "unexpected root element"},
		{"malformed XML", "sp", `<EntityDescriptor`, "unable to parse SP metadata"},
		{"no element at all", "sp", `<!-- just a comment -->`, "no XML element"},
		{"empty name", "", bareEntity, "name is required"},
		{"name with slash", "a/b", bareEntity, "must not contain '/'"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSPServices(tc.base, []byte(tc.doc))
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got %q", tc.want, err)
			}
		})
	}
}
