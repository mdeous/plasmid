package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/utils"
)

type serviceView struct {
	Name     string
	EntityID string
	LoginURL string
}

// serviceLoginURL is the IdP-initiated login URL for a service, which needs no
// stored shortcut.
func (h *WebHandler) serviceLoginURL(name string) string {
	return fmt.Sprintf("%s/login/sp/%s", h.baseURL, name)
}

func (h *WebHandler) loadServices() []serviceView {
	names := h.listKeys("/services/")
	services := make([]serviceView, 0, len(names))
	for _, name := range names {
		var s samlidp.Service
		if err := h.store.Get("/services/"+name, &s); err != nil {
			h.logger.Error("failed to load service", "name", name, "error", err)
			continue
		}
		// The name comes from the store key, not s.Name: samlidp's
		// HandlePutService leaves that field empty, so a service registered
		// through "client sp-add" would otherwise render as a blank row whose
		// row actions and login URL address nothing.
		services = append(services, serviceView{
			Name:     name,
			EntityID: s.Metadata.EntityID,
			LoginURL: h.serviceLoginURL(name),
		})
	}
	return services
}

func (h *WebHandler) handleServices(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "services", map[string]any{
		"Active":   "services",
		"Services": h.loadServices(),
	})
}

func (h *WebHandler) handleServiceCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Checked before fetching so a bad name fails without the network round-trip;
	// ParseSPServices validates again for the other callers.
	name := strings.TrimSpace(r.FormValue("name"))
	if err := utils.ValidateEntityName(name); err != nil {
		http.Error(w, "Invalid service name: "+err.Error(), http.StatusBadRequest)
		return
	}

	var metadataBytes []byte
	if metadataXML := strings.TrimSpace(r.FormValue("metadata_xml")); metadataXML != "" {
		metadataBytes = []byte(metadataXML)
	} else if metadataSource := strings.TrimSpace(r.FormValue("metadata")); metadataSource != "" {
		var err error
		metadataBytes, err = utils.FetchSPMetadata(metadataSource)
		if err != nil {
			h.logger.Error("failed to fetch SP metadata", "source", metadataSource, "error", err)
			http.Error(w, "Failed to fetch metadata: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Metadata URL or XML is required", http.StatusBadRequest)
		return
	}

	services, err := utils.ParseSPServices(name, metadataBytes)
	if err != nil {
		h.logger.Error("failed to parse SP metadata", "error", err)
		http.Error(w, "Invalid metadata: "+err.Error(), http.StatusBadRequest)
		return
	}

	for _, svc := range services {
		// Register with the IdP via its handler, which updates both the store
		// and the in-memory service providers map used for SAML lookups.
		putReq := httptest.NewRequest("PUT", "/services/"+svc.Name, bytes.NewReader(svc.XML))
		putReq.SetPathValue("id", svc.Name)
		rec := httptest.NewRecorder()
		h.idpServer.HandlePutService(rec, putReq)
		if rec.Code >= 400 {
			// Entities registered before this one stay registered; they show up
			// on the next page load.
			h.logger.Error("failed to register service with IdP", "name", svc.Name, "status", rec.Code)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Re-store with the Name field set (HandlePutService doesn't populate it).
		service := samlidp.Service{Name: svc.Name, Metadata: svc.Descriptor}
		if err := h.store.Put("/services/"+svc.Name, &service); err != nil {
			h.logger.Error("failed to update service record", "error", err)
		}
	}

	// Rows go out only once every entity is registered: renderPartial writes to
	// the response, so a failure after the first row could no longer set a status.
	for _, svc := range services {
		h.renderPartial(w, "service_row", serviceView{
			Name:     svc.Name,
			EntityID: svc.Descriptor.EntityID,
			LoginURL: h.serviceLoginURL(svc.Name),
		})
	}
}

func (h *WebHandler) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	delReq := httptest.NewRequest("DELETE", "/services/"+name, nil)
	delReq.SetPathValue("id", name)
	rec := httptest.NewRecorder()
	h.idpServer.HandleDeleteService(rec, delReq)
	if rec.Code >= 400 {
		h.logger.Error("failed to delete service", "name", name, "status", rec.Code)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
