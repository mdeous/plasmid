package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/crewjam/saml/samlidp"
)

type shortcutView struct {
	Name     string
	LoginURL string
}

func (h *WebHandler) loadShortcuts() []shortcutView {
	names := h.listKeys("/shortcuts/")
	shortcuts := make([]shortcutView, 0, len(names))
	for _, name := range names {
		shortcuts = append(shortcuts, shortcutView{
			Name:     name,
			LoginURL: fmt.Sprintf("%s/login/%s", h.baseURL, name),
		})
	}
	return shortcuts
}

func (h *WebHandler) handleShortcuts(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "shortcuts", map[string]any{
		"Active":    "shortcuts",
		"Shortcuts": h.loadShortcuts(),
	})
}

func (h *WebHandler) handleShortcutCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	entityID := strings.TrimSpace(r.FormValue("entity_id"))
	if name == "" || entityID == "" {
		http.Error(w, "Name and SP Entity ID are required", http.StatusBadRequest)
		return
	}

	shortcut := samlidp.Shortcut{
		Name:              name,
		ServiceProviderID: entityID,
	}
	if err := h.store.Put("/shortcuts/"+name, &shortcut); err != nil {
		h.logger.Error("failed to create shortcut", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderPartial(w, "shortcut_row", shortcutView{
		Name:     name,
		LoginURL: fmt.Sprintf("%s/login/%s", h.baseURL, name),
	})
}

func (h *WebHandler) handleShortcutDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.store.Delete("/shortcuts/" + name); err != nil {
		h.logger.Error("failed to delete shortcut", "name", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
