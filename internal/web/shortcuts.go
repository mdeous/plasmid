package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/utils"
)

// reservedShortcutNames would shadow a public route: "/login/sp/{name}" is more
// specific than "/login/{shortcut}/{suffix}", so a shortcut called "sp" could
// never be reached in its URL-suffix form.
var reservedShortcutNames = []string{"sp"}

const (
	relayModeNone   = ""
	relayModeFixed  = "fixed"
	relayModeSuffix = "suffix"
)

type shortcutView struct {
	Name            string
	EntityID        string
	ServiceName     string
	Registered      bool
	RelayStateLabel string
	LoginURL        string
}

func isRelayStateMode(value string) bool {
	return value == relayModeNone || value == relayModeFixed || value == relayModeSuffix
}

func validateShortcutName(name string) error {
	if err := utils.ValidateEntityName(name); err != nil {
		return fmt.Errorf("invalid shortcut name: %v", err)
	}
	if slices.Contains(reservedShortcutNames, name) {
		return fmt.Errorf("%q is reserved: it would shadow the /login/sp/<service> route", name)
	}
	return nil
}

// relayStateLabel describes what a shortcut sends as RelayState. The cases are
// ordered the way samlidp resolves them: a non-nil fixed value wins over the
// suffix flag.
func relayStateLabel(s samlidp.Shortcut) string {
	switch {
	case s.RelayState != nil:
		return fmt.Sprintf("%q", *s.RelayState)
	case s.URISuffixAsRelayState:
		return "from URL suffix"
	default:
		return "—"
	}
}

func namesByEntityID(services []serviceView) map[string]string {
	names := make(map[string]string, len(services))
	for _, s := range services {
		names[s.EntityID] = s.Name
	}
	return names
}

// shortcutViewFor takes the name from the store key rather than the stored
// Name field: the key is what /login/{shortcut} matches, and records written
// through the REST API need not agree with it.
func (h *WebHandler) shortcutViewFor(name string, s samlidp.Shortcut, serviceNames map[string]string) shortcutView {
	serviceName, registered := serviceNames[s.ServiceProviderID]
	return shortcutView{
		Name:            name,
		EntityID:        s.ServiceProviderID,
		ServiceName:     serviceName,
		Registered:      registered,
		RelayStateLabel: relayStateLabel(s),
		LoginURL:        fmt.Sprintf("%s/login/%s", h.baseURL, name),
	}
}

func (h *WebHandler) shortcutViews(services []serviceView) []shortcutView {
	names := h.listKeys("/shortcuts/")
	serviceNames := namesByEntityID(services)
	shortcuts := make([]shortcutView, 0, len(names))
	for _, name := range names {
		var s samlidp.Shortcut
		if err := h.store.Get("/shortcuts/"+name, &s); err != nil {
			h.logger.Error("failed to load shortcut", "name", name, "error", err)
			continue
		}
		shortcuts = append(shortcuts, h.shortcutViewFor(name, s, serviceNames))
	}
	return shortcuts
}

func (h *WebHandler) handleShortcuts(w http.ResponseWriter, r *http.Request) {
	services := h.loadServices()
	h.renderPage(w, "shortcuts", map[string]any{
		"Active":    "shortcuts",
		"Shortcuts": h.shortcutViews(services),
		"Services":  services,
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
		http.Error(w, "Name and service provider are required", http.StatusBadRequest)
		return
	}
	if err := validateShortcutName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// A shortcut whose SP is not registered answers every login with a bare
	// 404, so the dashboard refuses to create one. The REST API and
	// "client login-add" stay permissive.
	serviceNames := namesByEntityID(h.loadServices())
	if _, ok := serviceNames[entityID]; !ok {
		http.Error(w, "No registered service with that entity ID", http.StatusBadRequest)
		return
	}

	mode := r.FormValue("relay_state_mode")
	if !isRelayStateMode(mode) {
		http.Error(w, "Unknown RelayState mode", http.StatusBadRequest)
		return
	}

	shortcut := samlidp.Shortcut{
		Name:              name,
		ServiceProviderID: entityID,
	}
	switch mode {
	case relayModeFixed:
		value := strings.TrimSpace(r.FormValue("relay_state"))
		if value == "" {
			http.Error(w, "RelayState value is required", http.StatusBadRequest)
			return
		}
		shortcut.RelayState = &value
	case relayModeSuffix:
		shortcut.URISuffixAsRelayState = true
	}

	if err := h.store.Put("/shortcuts/"+name, &shortcut); err != nil {
		h.logger.Error("failed to create shortcut", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderPartial(w, "shortcut_row", h.shortcutViewFor(name, shortcut, serviceNames))
}

func (h *WebHandler) handleShortcutRename(w http.ResponseWriter, r *http.Request) {
	oldName := r.PathValue("name")
	newName := strings.TrimSpace(r.Header.Get("HX-Prompt"))
	if newName == "" {
		http.Error(w, "New name is required", http.StatusBadRequest)
		return
	}
	if newName == oldName {
		http.Error(w, "New name is identical to the current name", http.StatusBadRequest)
		return
	}
	if err := validateShortcutName(newName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var s samlidp.Shortcut
	if err := h.store.Get("/shortcuts/"+oldName, &s); err != nil {
		http.Error(w, "Shortcut not found", http.StatusNotFound)
		return
	}

	if existing, err := h.store.List("/shortcuts/"); err == nil {
		if slices.Contains(existing, newName) {
			http.Error(w, "A shortcut with that name already exists", http.StatusConflict)
			return
		}
	}

	s.Name = newName
	if err := h.store.Put("/shortcuts/"+newName, &s); err != nil {
		h.logger.Error("failed to save renamed shortcut", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.store.Delete("/shortcuts/" + oldName); err != nil {
		h.logger.Error("failed to delete old shortcut name", "error", err)
		// Best effort — new one is already saved.
	}

	h.renderPartial(w, "shortcut_row", h.shortcutViewFor(newName, s, namesByEntityID(h.loadServices())))
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
