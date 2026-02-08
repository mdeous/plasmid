package web

import "net/http"

func (h *WebHandler) SetMetadataXML(xml string) {
	h.metadataXML = xml
}

func (h *WebHandler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}

	users := h.listKeys("/users/")
	services := h.listKeys("/services/")
	sessions := h.listKeys("/sessions/")
	shortcuts := h.listKeys("/shortcuts/")

	h.renderPage(w, "dashboard", map[string]any{
		"Active":        "dashboard",
		"UserCount":     len(users),
		"ServiceCount":  len(services),
		"SessionCount":  len(sessions),
		"ShortcutCount": len(shortcuts),
		"BaseURL":       h.baseURL,
		"MetadataXML":   h.metadataXML,
	})
}

func (h *WebHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	users := h.listKeys("/users/")
	services := h.listKeys("/services/")
	sessions := h.listKeys("/sessions/")
	shortcuts := h.listKeys("/shortcuts/")

	h.renderPartial(w, "stats", map[string]any{
		"UserCount":     len(users),
		"ServiceCount":  len(services),
		"SessionCount":  len(sessions),
		"ShortcutCount": len(shortcuts),
	})
}
