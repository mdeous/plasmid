package web

import (
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
}

func (h *WebHandler) handleInspector(w http.ResponseWriter, r *http.Request) {
	var exchanges []internalsml.SAMLExchange
	if h.inspector != nil {
		exchanges = h.inspector.List()
	}
	h.renderPage(w, "inspector", map[string]any{
		"Active":    "inspector",
		"Exchanges": exchanges,
	})
}

func (h *WebHandler) handleInspectorExchanges(w http.ResponseWriter, r *http.Request) {
	if h.inspector == nil {
		return
	}
	exchanges := h.inspector.List()
	if len(exchanges) == 0 {
		w.Write([]byte(`<p>No SAML exchanges captured yet. Trigger a SAML flow to see traffic here.</p>`))
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
		w.Write([]byte(`<tr><td>` + html.EscapeString(ex.Timestamp) + `</td><td>` + html.EscapeString(ex.Direction) + `</td><td><code>` + html.EscapeString(ex.Endpoint) + `</code></td><td>` + html.EscapeString(ex.ServiceProvider) + `</td><td>` + html.EscapeString(ex.NameID) + `</td><td>` + signed + `</td><td>` + tampered + `</td><td><button class="outline" hx-get="/ui/inspector/` + html.EscapeString(ex.ID) + `" hx-target="#exchange-detail" hx-swap="innerHTML">View</button></td></tr>`))
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
	h.renderPartial(w, "inspector_detail", exchange)
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

func (h *WebHandler) handleTamperSave(w http.ResponseWriter, r *http.Request) {
	if h.tamperConfig == nil {
		http.Error(w, "Tamper not configured", http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	enabled := r.FormValue("enabled") == "on"
	removeSignature := r.FormValue("remove_signature") == "on"
	signatureMode := r.FormValue("signature_mode")
	nameID := strings.TrimSpace(r.FormValue("name_id"))
	nameIDFormat := r.FormValue("name_id_format")
	issuer := strings.TrimSpace(r.FormValue("issuer"))
	audience := strings.TrimSpace(r.FormValue("audience"))
	relayState := strings.TrimSpace(r.FormValue("relay_state"))

	xswVariant := r.FormValue("xsw_variant")
	xswNameID := strings.TrimSpace(r.FormValue("xsw_nameid"))

	xxeEnabled := r.FormValue("xxe_enabled") == "on"
	xxeType := r.FormValue("xxe_type")
	xxeTarget := strings.TrimSpace(r.FormValue("xxe_target"))
	xxePlacement := r.FormValue("xxe_placement")
	xxeCustom := strings.TrimSpace(r.FormValue("xxe_custom"))

	commentInjection := r.FormValue("comment_injection") == "on"
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

	h.tamperConfig.Update(internalsml.TamperUpdateInput{
		Enabled:          enabled,
		RemoveSignature:  removeSignature,
		SignatureMode:    signatureMode,
		NameID:           nameID,
		NameIDFormat:     nameIDFormat,
		Issuer:           issuer,
		Audience:         audience,
		RelayState:       relayState,
		InjectAttributes: attrs,
		XSWVariant:       xswVariant,
		XSWNameID:        xswNameID,
		XXEEnabled:       xxeEnabled,
		XXEType:          xxeType,
		XXETarget:        xxeTarget,
		XXEPlacement:     xxePlacement,
		XXECustom:        xxeCustom,
		CommentInjection: commentInjection,
		CommentPosition:  commentPosition,
	})
	http.Redirect(w, r, "/ui/tamper", http.StatusSeeOther)
}
