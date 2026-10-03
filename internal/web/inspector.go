package web

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"

	internalsml "github.com/mdeous/plasmid/internal/saml"
)

func (h *WebHandler) SetInspector(inspector *internalsml.Inspector) {
	h.inspector = inspector
}

func (h *WebHandler) SetTamperConfig(tc *internalsml.TamperConfig) {
	h.tamperConfig = tc
}

func (h *WebHandler) RegisterInspectorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/inspector", h.handleInspector)
	mux.HandleFunc("GET /ui/inspector/exchanges", h.handleInspectorExchanges)
	mux.HandleFunc("GET /ui/inspector/close", h.handleInspectorClose)
	mux.HandleFunc("GET /ui/inspector/{id}/replay", h.handleReplay)
	mux.HandleFunc("GET /ui/inspector/{id}", h.handleInspectorDetail)
	mux.HandleFunc("POST /ui/inspector/clear", h.handleInspectorClear)
	mux.HandleFunc("GET /ui/tamper", h.handleTamper)
	mux.HandleFunc("POST /ui/tamper", h.handleTamperSave)
	mux.HandleFunc("POST /ui/tamper/disable", h.handleTamperDisable)
	mux.HandleFunc("POST /ui/tamper/preview", h.handleTamperPreview)
}

// tamperBannerSummary returns a short human-readable description of the active
// tamper config, or empty string if tampering is disabled. Used by layout.html
// to display a sticky warning strip on every page.
func (h *WebHandler) tamperBannerSummary() string {
	if h.tamperConfig == nil || !h.tamperConfig.IsEnabled() {
		return ""
	}
	cfg := h.tamperConfig.GetConfig()
	var parts []string
	if cfg.RemoveSignature {
		parts = append(parts, "remove sig (pre-sign)")
	}
	if cfg.SignatureMode != "" {
		parts = append(parts, "sig:"+cfg.SignatureMode)
	}
	if cfg.SignKeyMode != "" {
		parts = append(parts, "key:"+cfg.SignKeyMode)
	}
	if cfg.ParserDiffMode != "" {
		parts = append(parts, "pdiff:"+cfg.ParserDiffMode)
	}
	if cfg.NameID != "" {
		parts = append(parts, "NameID override")
	}
	if cfg.NameIDFormat != "" {
		parts = append(parts, "NameID format override")
	}
	if cfg.Issuer != "" {
		parts = append(parts, "Issuer override")
	}
	if cfg.Audience != "" {
		parts = append(parts, "Audience override")
	}
	if cfg.InResponseTo != "" {
		parts = append(parts, "InResponseTo override")
	}
	if cfg.RelayState != "" {
		parts = append(parts, "RelayState override")
	}
	if cfg.XSWVariant != "" {
		parts = append(parts, cfg.XSWVariant)
	}
	if cfg.SendUnencrypted {
		parts = append(parts, "unencrypted assertion")
	}
	if cfg.CommentInjection {
		parts = append(parts, "comment injection")
	}
	if cfg.XXEEnabled {
		parts = append(parts, "XXE:"+cfg.XXEType)
	}
	if n := len(cfg.InjectAttributes); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d attr", n))
	}
	if len(parts) == 0 {
		return "enabled (no transforms selected)"
	}
	return strings.Join(parts, " · ")
}

func (h *WebHandler) handleInspector(w http.ResponseWriter, r *http.Request) {
	var exchanges []internalsml.SAMLExchange
	if h.inspector != nil {
		exchanges = h.inspector.List()
	}
	data := map[string]any{
		"Active":    "inspector",
		"Exchanges": exchanges,
	}
	if openID := r.URL.Query().Get("open"); openID != "" && h.inspector != nil {
		if ex := h.inspector.Get(openID); ex != nil {
			data["OpenExchange"] = struct {
				*internalsml.SAMLExchange
				PrettyXML string
			}{
				SAMLExchange: ex,
				PrettyXML:    prettyXML(ex.RawXML),
			}
		}
	}
	h.renderPage(w, "inspector", data)
}

func (h *WebHandler) handleInspectorExchanges(w http.ResponseWriter, r *http.Request) {
	if h.inspector == nil {
		return
	}
	h.renderPartial(w, "inspector_table", h.inspector.List())
}

func (h *WebHandler) handleInspectorDetail(w http.ResponseWriter, r *http.Request) {
	if h.inspector == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	exchange := h.inspector.Get(id)
	if exchange == nil {
		http.NotFound(w, r)
		return
	}
	view := struct {
		*internalsml.SAMLExchange
		PrettyXML string
	}{
		SAMLExchange: exchange,
		PrettyXML:    prettyXML(exchange.RawXML),
	}
	h.renderPartial(w, "inspector_detail", view)
}

func (h *WebHandler) handleInspectorClose(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<p><em>Select an exchange above to view details.</em></p>`))
}

func (h *WebHandler) handleInspectorClear(w http.ResponseWriter, r *http.Request) {
	if h.inspector != nil {
		h.inspector.Clear()
	}
	http.Redirect(w, r, "/ui/inspector", http.StatusSeeOther)
}

func (h *WebHandler) handleTamper(w http.ResponseWriter, r *http.Request) {
	var config internalsml.TamperConfigSnapshot
	if h.tamperConfig != nil {
		config = h.tamperConfig.GetConfig()
	}
	h.renderPage(w, "tamper", map[string]any{
		"Active":          "tamper",
		"Config":          config,
		"SignKeyModes":    internalsml.SignKeyModeOptions(),
		"ParserDiffModes": internalsml.ParserDiffModeOptions(),
	})
}

func (h *WebHandler) handleReplay(w http.ResponseWriter, r *http.Request) {
	if h.inspector == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	exchange := h.inspector.Get(id)
	if exchange == nil {
		http.NotFound(w, r)
		return
	}
	if exchange.Direction != "Response" || exchange.RawBase64 == "" {
		http.Error(w, "No replayable response data", http.StatusBadRequest)
		return
	}
	h.renderPartial(w, "replay_form", exchange)
}

// signKeyMode drops anything the form did not offer, so a hand-crafted POST
// cannot push an unknown mode into the config and fail every later response.
func signKeyMode(value string) string {
	if value == "" || internalsml.IsSignKeyMode(value) {
		return value
	}
	return ""
}

// parserDiffMode drops anything the form did not offer. Only validated payloads
// are offered, so this also keeps an unvalidated mode from being posted by hand.
func parserDiffMode(value string) string {
	if value == "" || internalsml.IsParserDiffMode(value) {
		return value
	}
	return ""
}

func parseTamperForm(r *http.Request) internalsml.TamperUpdateInput {
	commentPosition, _ := strconv.Atoi(r.FormValue("comment_position"))

	attrNames := r.Form["attr_name"]
	attrValues := r.Form["attr_value"]
	var attrs []internalsml.TamperAttribute
	for i := range attrNames {
		name := strings.TrimSpace(attrNames[i])
		if name == "" {
			continue
		}
		value := ""
		if i < len(attrValues) {
			value = strings.TrimSpace(attrValues[i])
		}
		attrs = append(attrs, internalsml.TamperAttribute{Name: name, Value: value})
	}

	return internalsml.TamperUpdateInput{
		Enabled:          r.FormValue("enabled") == "on",
		RemoveSignature:  r.FormValue("remove_signature") == "on",
		SignatureMode:    r.FormValue("signature_mode"),
		NameID:           strings.TrimSpace(r.FormValue("name_id")),
		NameIDFormat:     r.FormValue("name_id_format"),
		Issuer:           strings.TrimSpace(r.FormValue("issuer")),
		Audience:         strings.TrimSpace(r.FormValue("audience")),
		InResponseTo:     strings.TrimSpace(r.FormValue("in_response_to")),
		RelayState:       strings.TrimSpace(r.FormValue("relay_state")),
		InjectAttributes: attrs,
		XSWVariant:       r.FormValue("xsw_variant"),
		XSWNameID:        strings.TrimSpace(r.FormValue("xsw_nameid")),
		SendUnencrypted:  r.FormValue("send_unencrypted") == "on",
		XXEEnabled:       r.FormValue("xxe_enabled") == "on",
		XXEType:          r.FormValue("xxe_type"),
		XXETarget:        strings.TrimSpace(r.FormValue("xxe_target")),
		XXEPlacement:     r.FormValue("xxe_placement"),
		XXECustom:        strings.TrimSpace(r.FormValue("xxe_custom")),
		CommentInjection: r.FormValue("comment_injection") == "on",
		CommentPosition:  commentPosition,
		SignKeyMode:      signKeyMode(r.FormValue("sign_key_mode")),
		ParserDiffMode:   parserDiffMode(r.FormValue("parser_diff_mode")),
	}
}

func (h *WebHandler) handleTamperSave(w http.ResponseWriter, r *http.Request) {
	if h.tamperConfig == nil {
		http.Error(w, "Tamper not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	h.tamperConfig.Update(parseTamperForm(r))
	http.Redirect(w, r, "/ui/tamper", http.StatusSeeOther)
}

func (h *WebHandler) handleTamperDisable(w http.ResponseWriter, r *http.Request) {
	if h.tamperConfig != nil {
		// Converting the snapshot keeps every setting; only Enabled changes.
		in := h.tamperConfig.GetConfig().UpdateInput()
		in.Enabled = false
		h.tamperConfig.Update(in)
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/ui/tamper"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// handleTamperPreview renders a preview of the pending tamper config applied
// against the most recent captured Response exchange. Returns an HTML partial
// to be swapped into the tamper page.
func (h *WebHandler) handleTamperPreview(w http.ResponseWriter, r *http.Request) {
	if h.tamperConfig == nil {
		http.Error(w, "Tamper not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	proposed := parseTamperForm(r)

	var warnings []string
	if proposed.SignatureMode != "" && proposed.XSWVariant != "" {
		warnings = append(warnings, "Signature Mode combined with XSW: the signed structure will be re-wrapped, which may defeat your signature-mode test.")
	}
	if proposed.XXEEnabled && proposed.XXEType == "custom" && strings.TrimSpace(proposed.XXECustom) == "" {
		warnings = append(warnings, "XXE type 'custom' requires a DOCTYPE in the custom field.")
	}
	if proposed.SignKeyMode != "" && !proposed.SendUnencrypted {
		warnings = append(warnings, "Signing key attack needs a plaintext assertion: with an encrypted assertion the signature is sealed inside EncryptedAssertion and the attack is skipped. Turn on \"Send assertion unencrypted\".")
	}
	if proposed.SignKeyMode != "" && proposed.SignatureMode != "" {
		warnings = append(warnings, "Signing key attack combined with Signature Manipulation: the signature is replaced first and then stripped or corrupted, which leaves nothing for the SP to check the certificate against.")
	}
	if proposed.ParserDiffMode != "" && !proposed.SendUnencrypted {
		warnings = append(warnings, "Parser differential attacks rewrite the assertion and the IDs around it: with an encrypted assertion there is nothing to rewrite and the attack is skipped. Turn on \"Send assertion unencrypted\".")
	}
	if proposed.ParserDiffMode != "" && proposed.SignatureMode != "" {
		warnings = append(warnings, "Parser differential combined with Signature Manipulation: the signature this mode carefully builds is then stripped or corrupted, so the SP never evaluates the differential.")
	}
	if proposed.ParserDiffMode != "" && proposed.XSWVariant != "" {
		warnings = append(warnings, "Parser differential combined with XSW: the wrap re-arranges the structure the differential depends on.")
	}
	if proposed.ParserDiffMode == internalsml.ParserDiffVoidC14N && proposed.SignKeyMode != "" {
		warnings = append(warnings, "Void canonicalization signs with the real IdP key on purpose, so the SP's configured certificate matches and the only thing under test is the canonicalization bug. A signing key attack replaces that signature and muddies the result.")
	}
	if proposed.ParserDiffMode == internalsml.ParserDiffVoidC14N && proposed.NameID == "" {
		warnings = append(warnings, "Void canonicalization on its own changes nothing the SP can report back. Set a NameID override to find out whether it accepts a forged subject.")
	}
	if proposed.Enabled && !proposed.RemoveSignature && proposed.SignatureMode == "" &&
		proposed.SignKeyMode == "" && proposed.ParserDiffMode == "" &&
		proposed.NameID == "" && proposed.NameIDFormat == "" && proposed.Issuer == "" &&
		proposed.Audience == "" && proposed.InResponseTo == "" &&
		proposed.RelayState == "" && proposed.XSWVariant == "" &&
		!proposed.XXEEnabled && !proposed.CommentInjection && !proposed.SendUnencrypted &&
		len(proposed.InjectAttributes) == 0 {
		warnings = append(warnings, "Tampering is enabled but no transforms are configured — the assertion will pass through unchanged.")
	}

	if h.inspector == nil {
		h.writeTamperPreview(w, "", "", warnings, "Inspector is not available.")
		return
	}

	// Find the most recent Response with RawBase64.
	var lastResponse *internalsml.SAMLExchange
	for _, ex := range h.inspector.List() {
		if ex.Direction == "Response" && ex.RawBase64 != "" {
			e := ex
			lastResponse = &e
			break
		}
	}
	if lastResponse == nil {
		h.writeTamperPreview(w, "", "", warnings, "No captured SAML response available to preview against. Trigger a successful SAML flow first, then retry.")
		return
	}

	originalBytes, err := base64.StdEncoding.DecodeString(lastResponse.RawBase64)
	if err != nil {
		h.writeTamperPreview(w, "", "", warnings, "Captured response has invalid base64: "+err.Error())
		return
	}
	original := prettyXML(string(originalBytes))

	if internalsml.IsEncryptedAssertion(originalBytes) && (proposed.XSWVariant != "" || proposed.CommentInjection) {
		if proposed.SendUnencrypted {
			warnings = append(warnings, `The captured response has an encrypted assertion, so the preview below cannot show XSW or comment injection. With "Send assertion unencrypted" on, the next live flow sends plaintext and the transforms will apply.`)
		} else {
			warnings = append(warnings, `The captured response has an encrypted assertion: XSW and comment injection rewrite assertion XML and will be skipped. Enable "Send assertion unencrypted" to make them apply.`)
		}
	}

	// Build a throwaway TamperConfig with the proposed values and run the
	// post-sign transform against the captured response.
	// Carry the live attack key material across, or every key-dependent mode
	// would preview as a transform failure.
	tmp := h.tamperConfig.CloneForPreview()
	tmp.Update(proposed)

	if !tmp.NeedsPostSignTransform() {
		h.writeTamperPreview(w, original, original, warnings, "Pre-sign-only transforms cannot be previewed without re-running the assertion maker. Only the original captured response is shown.")
		return
	}

	tamperedB64, _, err := internalsml.TransformSAMLResponse(lastResponse.RawBase64, tmp, h.logger)
	if err != nil {
		h.writeTamperPreview(w, original, "", warnings, "Transform failed: "+err.Error())
		return
	}
	tamperedBytes, err := base64.StdEncoding.DecodeString(tamperedB64)
	if err != nil {
		h.writeTamperPreview(w, original, "", warnings, "Transformed response has invalid base64: "+err.Error())
		return
	}
	h.writeTamperPreview(w, original, prettyXML(string(tamperedBytes)), warnings, "")
}

func (h *WebHandler) writeTamperPreview(w http.ResponseWriter, original, tampered string, warnings []string, note string) {
	var b strings.Builder
	b.WriteString(`<section class="tamper-preview" id="tamper-preview"><h3>Preview</h3>`)
	for _, warn := range warnings {
		b.WriteString(`<div class="preview-warning">⚠ ` + html.EscapeString(warn) + `</div>`)
	}
	if note != "" {
		b.WriteString(`<p class="empty-state">` + html.EscapeString(note) + `</p>`)
	}
	if original != "" || tampered != "" {
		b.WriteString(`<div class="preview-columns"><div class="preview-column"><h4>Original</h4><pre class="xml-display">`)
		b.WriteString(html.EscapeString(original))
		b.WriteString(`</pre></div><div class="preview-column"><h4>Tampered</h4><pre class="xml-display">`)
		b.WriteString(html.EscapeString(tampered))
		b.WriteString(`</pre></div></div>`)
	}
	b.WriteString(`</section>`)
	w.Write([]byte(b.String()))
}
