package saml

import (
	"strings"
	"sync"

	crewsaml "github.com/crewjam/saml"
)

type TamperAttribute struct {
	Name  string
	Value string
}

type TamperModification struct {
	Field    string
	OldValue string
	NewValue string
}

type TamperConfig struct {
	mu               sync.RWMutex
	Enabled          bool
	RemoveSignature  bool
	SignatureMode    string
	NameID           string
	NameIDFormat     string
	Issuer           string
	Audience         string
	RelayState       string
	InjectAttributes []TamperAttribute
	XSWVariant       string
	XSWNameID        string
	SendUnencrypted  bool
	XXEEnabled       bool
	XXEType          string
	XXETarget        string
	XXEPlacement     string
	XXECustom        string
	CommentInjection bool
	CommentPosition  int
	lastMods         []TamperModification
}

func NewTamperConfig() *TamperConfig {
	return &TamperConfig{}
}

func (tc *TamperConfig) IsEnabled() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.Enabled
}

func (tc *TamperConfig) ShouldRemoveSignature() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.Enabled && tc.RemoveSignature
}

func (tc *TamperConfig) NeedsPostSignTransform() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.Enabled && (tc.XSWVariant != "" || tc.XXEEnabled || tc.SignatureMode != "" || tc.CommentInjection)
}

// NeedsResponseRewrite reports whether the outgoing response has to be buffered
// so it can be modified. That covers the post-sign XML transforms plus the
// RelayState override, which rewrites a form field rather than the assertion.
func (tc *TamperConfig) NeedsResponseRewrite() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	postSign := tc.XSWVariant != "" || tc.XXEEnabled || tc.SignatureMode != "" || tc.CommentInjection
	return tc.Enabled && (postSign || tc.RelayState != "")
}

func (tc *TamperConfig) ConsumeModifications() []TamperModification {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	mods := tc.lastMods
	tc.lastMods = nil
	return mods
}

type TamperConfigSnapshot struct {
	Enabled          bool
	RemoveSignature  bool
	SignatureMode    string
	NameID           string
	NameIDFormat     string
	Issuer           string
	Audience         string
	RelayState       string
	InjectAttributes []TamperAttribute
	XSWVariant       string
	XSWNameID        string
	SendUnencrypted  bool
	XXEEnabled       bool
	XXEType          string
	XXETarget        string
	XXEPlacement     string
	XXECustom        string
	CommentInjection bool
	CommentPosition  int
}

func (tc *TamperConfig) GetConfig() TamperConfigSnapshot {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	snap := TamperConfigSnapshot{
		Enabled:          tc.Enabled,
		RemoveSignature:  tc.RemoveSignature,
		SignatureMode:    tc.SignatureMode,
		NameID:           tc.NameID,
		NameIDFormat:     tc.NameIDFormat,
		Issuer:           tc.Issuer,
		Audience:         tc.Audience,
		RelayState:       tc.RelayState,
		InjectAttributes: make([]TamperAttribute, len(tc.InjectAttributes)),
		XSWVariant:       tc.XSWVariant,
		XSWNameID:        tc.XSWNameID,
		SendUnencrypted:  tc.SendUnencrypted,
		XXEEnabled:       tc.XXEEnabled,
		XXEType:          tc.XXEType,
		XXETarget:        tc.XXETarget,
		XXEPlacement:     tc.XXEPlacement,
		XXECustom:        tc.XXECustom,
		CommentInjection: tc.CommentInjection,
		CommentPosition:  tc.CommentPosition,
	}
	copy(snap.InjectAttributes, tc.InjectAttributes)
	return snap
}

type TamperUpdateInput struct {
	Enabled          bool
	RemoveSignature  bool
	SignatureMode    string
	NameID           string
	NameIDFormat     string
	Issuer           string
	Audience         string
	RelayState       string
	InjectAttributes []TamperAttribute
	XSWVariant       string
	XSWNameID        string
	SendUnencrypted  bool
	XXEEnabled       bool
	XXEType          string
	XXETarget        string
	XXEPlacement     string
	XXECustom        string
	CommentInjection bool
	CommentPosition  int
}

func (tc *TamperConfig) Update(input TamperUpdateInput) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.Enabled = input.Enabled
	tc.RemoveSignature = input.RemoveSignature
	tc.SignatureMode = input.SignatureMode
	tc.NameID = input.NameID
	tc.NameIDFormat = input.NameIDFormat
	tc.Issuer = input.Issuer
	tc.Audience = input.Audience
	tc.RelayState = input.RelayState
	tc.InjectAttributes = input.InjectAttributes
	tc.XSWVariant = input.XSWVariant
	tc.XSWNameID = input.XSWNameID
	tc.SendUnencrypted = input.SendUnencrypted
	tc.XXEEnabled = input.XXEEnabled
	tc.XXEType = input.XXEType
	tc.XXETarget = input.XXETarget
	tc.XXEPlacement = input.XXEPlacement
	tc.XXECustom = input.XXECustom
	tc.CommentInjection = input.CommentInjection
	tc.CommentPosition = input.CommentPosition
}

// ResetModifications drops queued modifications. Called at the start of each
// intercepted request so leftovers from a flow that never produced a
// SAMLResponse are not reported against the next exchange.
func (tc *TamperConfig) ResetModifications() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.lastMods = nil
}

func (tc *TamperConfig) RecordModification(mod TamperModification) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.lastMods = append(tc.lastMods, mod)
}

type TamperableAssertionMaker struct {
	Config *TamperConfig
}

func (t TamperableAssertionMaker) MakeAssertion(req *crewsaml.IdpAuthnRequest, session *crewsaml.Session) error {
	if err := (crewsaml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}

	if t.Config == nil || !t.Config.IsEnabled() {
		return nil
	}

	t.Config.mu.Lock()
	defer t.Config.mu.Unlock()

	assertion := req.Assertion
	var mods []TamperModification

	if t.Config.NameID != "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		mods = append(mods, TamperModification{"NameID", assertion.Subject.NameID.Value, t.Config.NameID})
		assertion.Subject.NameID.Value = t.Config.NameID
	}

	if t.Config.NameIDFormat != "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		mods = append(mods, TamperModification{"NameID Format", assertion.Subject.NameID.Format, t.Config.NameIDFormat})
		assertion.Subject.NameID.Format = t.Config.NameIDFormat
	}

	if t.Config.Issuer != "" {
		mods = append(mods, TamperModification{"Issuer", assertion.Issuer.Value, t.Config.Issuer})
		assertion.Issuer.Value = t.Config.Issuer
	}

	if t.Config.Audience != "" && assertion.Conditions != nil {
		for i := range assertion.Conditions.AudienceRestrictions {
			old := assertion.Conditions.AudienceRestrictions[i].Audience.Value
			mods = append(mods, TamperModification{"Audience", old, t.Config.Audience})
			assertion.Conditions.AudienceRestrictions[i].Audience.Value = t.Config.Audience
		}
	}

	for _, attr := range t.Config.InjectAttributes {
		if attr.Name == "" {
			continue
		}
		found := false
		for i, existing := range assertion.AttributeStatements {
			for j, a := range existing.Attributes {
				if a.FriendlyName == attr.Name || a.Name == attr.Name {
					var oldVals []string
					for _, v := range a.Values {
						oldVals = append(oldVals, v.Value)
					}
					old := ""
					if len(oldVals) > 0 {
						old = strings.Join(oldVals, ", ")
					}
					mods = append(mods, TamperModification{"Attribute: " + attr.Name, old, attr.Value})
					assertion.AttributeStatements[i].Attributes[j].Values = []crewsaml.AttributeValue{
						{Value: attr.Value},
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			if len(assertion.AttributeStatements) == 0 {
				assertion.AttributeStatements = []crewsaml.AttributeStatement{{}}
			}
			mods = append(mods, TamperModification{"Attribute: " + attr.Name, "(added)", attr.Value})
			assertion.AttributeStatements[0].Attributes = append(
				assertion.AttributeStatements[0].Attributes,
				crewsaml.Attribute{
					Name:       attr.Name,
					NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					Values:     []crewsaml.AttributeValue{{Value: attr.Value}},
				},
			)
		}
	}

	// Both branches set AssertionEl, which pre-empts the library's
	// sign-and-encrypt step in MakeResponse.
	switch {
	case t.Config.RemoveSignature:
		mods = append(mods, TamperModification{"Signature", "present", "removed"})
		req.AssertionEl = req.Assertion.Element()
	case t.Config.SendUnencrypted:
		encrypted := encryptionCapable(req.SPSSODescriptor)
		if err := makeSignedPlaintextAssertion(req); err != nil {
			return err
		}
		if encrypted {
			mods = append(mods, TamperModification{"Assertion Encryption", "enabled", "disabled"})
		}
	}

	t.Config.lastMods = append(t.Config.lastMods, mods...)

	return nil
}

// makeSignedPlaintextAssertion builds the assertion element with the SP's
// encryption certificates hidden, so the library signs it but sends it in the
// clear. Post-sign transforms such as XSW can only rewrite a plaintext
// assertion. Signing uses the IdP's own key, so dropping SP key descriptors
// does not affect it.
func makeSignedPlaintextAssertion(req *crewsaml.IdpAuthnRequest) error {
	if req.SPSSODescriptor == nil {
		return req.MakeAssertionEl()
	}
	original := req.SPSSODescriptor
	filtered := *original
	filtered.KeyDescriptors = signingOnly(original.KeyDescriptors)
	req.SPSSODescriptor = &filtered
	defer func() { req.SPSSODescriptor = original }()
	return req.MakeAssertionEl()
}

func signingOnly(descriptors []crewsaml.KeyDescriptor) []crewsaml.KeyDescriptor {
	kept := make([]crewsaml.KeyDescriptor, 0, len(descriptors))
	for _, kd := range descriptors {
		if kd.Use == "signing" {
			kept = append(kept, kd)
		}
	}
	return kept
}

// encryptionCapable mirrors the library's certificate lookup: a descriptor
// marked for encryption, or failing that any descriptor with no declared use
// that carries a certificate.
func encryptionCapable(descriptor *crewsaml.SPSSODescriptor) bool {
	if descriptor == nil {
		return false
	}
	for _, kd := range descriptor.KeyDescriptors {
		if kd.Use == "encryption" {
			return true
		}
	}
	for _, kd := range descriptor.KeyDescriptors {
		if kd.Use == "" && len(kd.KeyInfo.X509Data.X509Certificates) > 0 &&
			kd.KeyInfo.X509Data.X509Certificates[0].Data != "" {
			return true
		}
	}
	return false
}
