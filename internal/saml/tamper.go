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
	NameID           string
	NameIDFormat     string
	Issuer           string
	Audience         string
	InjectAttributes []TamperAttribute
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
	NameID           string
	NameIDFormat     string
	Issuer           string
	Audience         string
	InjectAttributes []TamperAttribute
}

func (tc *TamperConfig) GetConfig() TamperConfigSnapshot {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	snap := TamperConfigSnapshot{
		Enabled:          tc.Enabled,
		RemoveSignature:  tc.RemoveSignature,
		NameID:           tc.NameID,
		NameIDFormat:     tc.NameIDFormat,
		Issuer:           tc.Issuer,
		Audience:         tc.Audience,
		InjectAttributes: make([]TamperAttribute, len(tc.InjectAttributes)),
	}
	copy(snap.InjectAttributes, tc.InjectAttributes)
	return snap
}

func (tc *TamperConfig) Update(enabled, removeSignature bool, nameID, nameIDFormat, issuer, audience string, attrs []TamperAttribute) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.Enabled = enabled
	tc.RemoveSignature = removeSignature
	tc.NameID = nameID
	tc.NameIDFormat = nameIDFormat
	tc.Issuer = issuer
	tc.Audience = audience
	tc.InjectAttributes = attrs
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

	if t.Config.Audience != "" {
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

	if t.Config.RemoveSignature {
		mods = append(mods, TamperModification{"Signature", "present", "removed"})
		req.AssertionEl = req.Assertion.Element()
	}

	t.Config.lastMods = mods

	return nil
}
