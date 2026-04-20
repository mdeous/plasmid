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
	if cfg.RelayState != "" {
		parts = append(parts, "RelayState override")
	}
	if cfg.XSWVariant != "" {
		parts = append(parts, cfg.XSWVariant)
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
	exchanges := h.inspector.List()
	if len(exchanges) == 0 {
		w.Write([]byte(`<p class="empty-state">No SAML exchanges captured yet. Trigger a flow via a <a href="/ui/shortcuts">login shortcut</a> or SP-initiated SSO to see traffic here.</p>`))
		return
	}

	w.Write([]byte(`<table><thead><tr><th>Time</th><th>Direction</th><th>Endpoint</th><th>SP</th><th>NameID</th><th>Signed</th><th>Tampered</th><th>Actions</th></tr></thead><tbody>`))
	for _, ex := range exchanges {
		signed := `<span class="badge badge-red">No</span>`
		if ex.Signed {
			signed = `<span class="badge badge-green">Yes</span>`
		}
		tampered := ""
		if ex.Tampered {
			tampered = `<span class="badge badge-red">Yes</span>`
		}
		w.Write([]byte(`<tr class="inspector-row" data-direction="` + html.EscapeString(ex.Direction) + `" data-sp="` + html.EscapeString(strings.ToLower(ex.ServiceProvider)) + `" data-nameid="` + html.EscapeString(strings.ToLower(ex.NameID)) + `" data-endpoint="` + html.EscapeString(strings.ToLower(ex.Endpoint)) + `"><td>` + html.EscapeString(ex.Timestamp) + `</td><td>` + html.EscapeString(ex.Direction) + `</td><td><code>` + html.EscapeString(ex.Endpoint) + `</code></td><td>` + html.EscapeString(ex.ServiceProvider) + `</td><td>` + html.EscapeString(ex.NameID) + `</td><td>` + signed + `</td><td>` + tampered + `</td><td><button class="outline" hx-get="/ui/inspector/` + html.EscapeString(ex.ID) + `" hx-target="#exchange-detail" hx-swap="innerHTML">View</button></td></tr>`))
	}
	w.Write([]byte(`</tbody></table>`))
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
		"Active": "tamper",
		"Config": config,
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
		RelayState:       strings.TrimSpace(r.FormValue("relay_state")),
		InjectAttributes: attrs,
		XSWVariant:       r.FormValue("xsw_variant"),
		XSWNameID:        strings.TrimSpace(r.FormValue("xsw_nameid")),
		XXEEnabled:       r.FormValue("xxe_enabled") == "on",
		XXEType:          r.FormValue("xxe_type"),
		XXETarget:        strings.TrimSpace(r.FormValue("xxe_target")),
		XXEPlacement:     r.FormValue("xxe_placement"),
		XXECustom:        strings.TrimSpace(r.FormValue("xxe_custom")),
		CommentInjection: r.FormValue("comment_injection") == "on",
		CommentPosition:  commentPosition,
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
		cur := h.tamperConfig.GetConfig()
		cur.Enabled = false
		h.tamperConfig.Update(internalsml.TamperUpdateInput{
			Enabled:          false,
			RemoveSignature:  cur.RemoveSignature,
			SignatureMode:    cur.SignatureMode,
			NameID:           cur.NameID,
			NameIDFormat:     cur.NameIDFormat,
			Issuer:           cur.Issuer,
			Audience:         cur.Audience,
			RelayState:       cur.RelayState,
			InjectAttributes: cur.InjectAttributes,
			XSWVariant:       cur.XSWVariant,
			XSWNameID:        cur.XSWNameID,
			XXEEnabled:       cur.XXEEnabled,
			XXEType:          cur.XXEType,
			XXETarget:        cur.XXETarget,
			XXEPlacement:     cur.XXEPlacement,
			XXECustom:        cur.XXECustom,
			CommentInjection: cur.CommentInjection,
			CommentPosition:  cur.CommentPosition,
		})
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
	if proposed.Enabled && !proposed.RemoveSignature && proposed.SignatureMode == "" &&
		proposed.NameID == "" && proposed.NameIDFormat == "" && proposed.Issuer == "" &&
		proposed.Audience == "" && proposed.RelayState == "" && proposed.XSWVariant == "" &&
		!proposed.XXEEnabled && !proposed.CommentInjection && len(proposed.InjectAttributes) == 0 {
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

	// Build a throwaway TamperConfig with the proposed values and run the
	// post-sign transform against the captured response.
	tmp := internalsml.NewTamperConfig()
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
