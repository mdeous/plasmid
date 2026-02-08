package web

import (
	"net/http"
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
		w.Write([]byte(`<tr><td>` + ex.Timestamp + `</td><td>` + ex.Direction + `</td><td><code>` + ex.Endpoint + `</code></td><td>` + ex.ServiceProvider + `</td><td>` + ex.NameID + `</td><td>` + signed + `</td><td>` + tampered + `</td><td><button class="outline" hx-get="/ui/inspector/` + ex.ID + `" hx-target="#exchange-detail" hx-swap="innerHTML">View</button></td></tr>`))
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
	nameID := strings.TrimSpace(r.FormValue("name_id"))
	nameIDFormat := r.FormValue("name_id_format")
	issuer := strings.TrimSpace(r.FormValue("issuer"))
	audience := strings.TrimSpace(r.FormValue("audience"))

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

	h.tamperConfig.Update(enabled, removeSignature, nameID, nameIDFormat, issuer, audience, attrs)
	http.Redirect(w, r, "/ui/tamper", http.StatusSeeOther)
}
