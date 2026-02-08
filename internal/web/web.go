package web

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/crewjam/saml/samlidp"
	internalsml "github.com/mdeous/plasmid/internal/saml"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type CertInfo struct {
	Subject      string
	Issuer       string
	NotBefore    string
	NotAfter     string
	SerialNumber string
	Fingerprint  string
}

type WebHandler struct {
	store        samlidp.Store
	idpServer    *samlidp.Server
	logger       *slog.Logger
	baseURL      string
	cert         *x509.Certificate
	metadataXML  string
	pages        map[string]*template.Template
	partials     *template.Template
	inspector    *internalsml.Inspector
	tamperConfig *internalsml.TamperConfig
}

func NewWebHandler(store samlidp.Store, idpServer *samlidp.Server, logger *slog.Logger, baseURL string, cert *x509.Certificate) (*WebHandler, error) {
	base, err := template.ParseFS(templateFS,
		"templates/layout.html",
		"templates/user_row.html",
		"templates/service_row.html",
		"templates/session_row.html",
		"templates/shortcut_row.html",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base templates: %v", err)
	}

	pageFiles := []string{
		"templates/dashboard.html",
		"templates/users.html",
		"templates/services.html",
		"templates/sessions.html",
		"templates/shortcuts.html",
		"templates/settings.html",
		"templates/inspector.html",
		"templates/tamper.html",
	}
	pages := make(map[string]*template.Template, len(pageFiles))
	for _, pf := range pageFiles {
		t, err := template.Must(base.Clone()).ParseFS(templateFS, pf)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %v", pf, err)
		}
		name := strings.TrimPrefix(pf, "templates/")
		name = strings.TrimSuffix(name, ".html")
		pages[name] = t
	}

	partials, err := template.ParseFS(templateFS,
		"templates/user_row.html",
		"templates/service_row.html",
		"templates/session_row.html",
		"templates/shortcut_row.html",
		"templates/stats.html",
		"templates/inspector_detail.html",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse partial templates: %v", err)
	}

	return &WebHandler{
		store:     store,
		idpServer: idpServer,
		logger:    logger,
		baseURL:   baseURL,
		cert:      cert,
		pages:     pages,
		partials:  partials,
	}, nil
}

func (h *WebHandler) RegisterRoutes(mux *http.ServeMux) {
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(staticContent))))

	mux.HandleFunc("GET /ui/", h.handleDashboard)
	mux.HandleFunc("GET /ui/api/stats", h.handleStats)

	mux.HandleFunc("GET /ui/users", h.handleUsers)
	mux.HandleFunc("POST /ui/users", h.handleUserCreate)
	mux.HandleFunc("DELETE /ui/users/{name}", h.handleUserDelete)

	mux.HandleFunc("GET /ui/services", h.handleServices)
	mux.HandleFunc("POST /ui/services", h.handleServiceCreate)
	mux.HandleFunc("DELETE /ui/services/{name}", h.handleServiceDelete)

	mux.HandleFunc("GET /ui/sessions", h.handleSessions)
	mux.HandleFunc("GET /ui/sessions/list", h.handleSessionsList)
	mux.HandleFunc("DELETE /ui/sessions/{id}", h.handleSessionDelete)

	mux.HandleFunc("GET /ui/shortcuts", h.handleShortcuts)
	mux.HandleFunc("POST /ui/shortcuts", h.handleShortcutCreate)
	mux.HandleFunc("DELETE /ui/shortcuts/{name}", h.handleShortcutDelete)

	mux.HandleFunc("GET /ui/settings", h.handleSettings)
}

func (h *WebHandler) renderPage(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, ok := data["Active"]; !ok {
		data["Active"] = ""
	}
	t, ok := h.pages[name]
	if !ok {
		h.logger.Error("template not found", "template", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		h.logger.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *WebHandler) renderPartial(w http.ResponseWriter, name string, data any) {
	if err := h.partials.ExecuteTemplate(w, name, data); err != nil {
		h.logger.Error("partial render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *WebHandler) certInfo() *CertInfo {
	if h.cert == nil {
		return nil
	}
	fingerprint := sha256.Sum256(h.cert.Raw)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return &CertInfo{
		Subject:      h.cert.Subject.String(),
		Issuer:       h.cert.Issuer.String(),
		NotBefore:    h.cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
		NotAfter:     h.cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
		SerialNumber: h.cert.SerialNumber.String(),
		Fingerprint:  strings.Join(parts, ":"),
	}
}

func (h *WebHandler) listKeys(prefix string) []string {
	keys, err := h.store.List(prefix)
	if err != nil {
		h.logger.Error("store list error", "prefix", prefix, "error", err)
		return nil
	}
	return keys
}

func LoginFormTemplate() (*template.Template, error) {
	return template.ParseFS(templateFS, "templates/login.html")
}
