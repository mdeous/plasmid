package web

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/utils"
)

type serviceView struct {
	Name     string
	EntityID string
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
		services = append(services, serviceView{
			Name:     s.Name,
			EntityID: s.Metadata.EntityID,
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

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
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

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataBytes, &metadata); err != nil {
		h.logger.Error("failed to parse SP metadata", "error", err)
		http.Error(w, "Invalid metadata XML: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Register with the IdP via its handler, which updates both the store
	// and the in-memory service providers map used for SAML lookups.
	putReq := httptest.NewRequest("PUT", "/services/"+name, bytes.NewReader(metadataBytes))
	putReq.SetPathValue("id", name)
	rec := httptest.NewRecorder()
	h.idpServer.HandlePutService(rec, putReq)
	if rec.Code >= 400 {
		h.logger.Error("failed to register service with IdP", "name", name, "status", rec.Code)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Re-store with the Name field set (HandlePutService doesn't populate it).
	service := samlidp.Service{Name: name, Metadata: metadata}
	if err := h.store.Put("/services/"+name, &service); err != nil {
		h.logger.Error("failed to update service record", "error", err)
	}

	h.renderPartial(w, "service_row", serviceView{
		Name:     name,
		EntityID: metadata.EntityID,
	})
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
