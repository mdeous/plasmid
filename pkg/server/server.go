package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"golang.org/x/crypto/bcrypt"

	internalsml "github.com/mdeous/plasmid/internal/saml"
	"github.com/mdeous/plasmid/internal/web"
)

type Plasmid struct {
	Host        string
	Port        int
	AdminHost   string
	AdminPort   int
	IDP         *samlidp.Server
	PublicMux   *http.ServeMux
	AdminMux    *http.ServeMux
	logger      *slog.Logger
	externalUrl string
	cert        *x509.Certificate
}

// adminUrl is the address an operator reaches the dashboard on. A wildcard
// bind address is reported back as loopback, since "0.0.0.0" is not something
// a browser can usefully follow.
func (p *Plasmid) adminUrl() string {
	host := p.AdminHost
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d", host, p.AdminPort)
}

func (p *Plasmid) Metadata() ([]byte, error) {
	metaDescriptor := p.IDP.IDP.Metadata()
	meta, err := xml.MarshalIndent(metaDescriptor, "", " ")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to serialize idp metadata: %v", err)
	}
	return meta, nil
}

func (p *Plasmid) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqUrl := strings.NewReplacer("\n", "", "\r", "").Replace(r.URL.String())
		p.logger.Info("request", "remote", r.RemoteAddr, "method", r.Method, "url", reqUrl)
		next.ServeHTTP(w, r)
	})
}

// BuildRoutes wires the public and admin muxes. The two are served on separate
// listeners: the public one carries only the SAML endpoints an SP has to reach,
// while the admin one carries the REST API, dashboard and inspector, none of
// which authenticate the caller and none of which belong on a public tunnel.
func (p *Plasmid) BuildRoutes() (*internalsml.Inspector, *internalsml.TamperConfig, error) {
	inspector := internalsml.NewInspector(100)
	tamperConfig := internalsml.NewTamperConfig()

	p.IDP.IDP.AssertionMaker = internalsml.TamperableAssertionMaker{Config: tamperConfig}
	tamperConfig.SetResigner(internalsml.NewResigner(p.cert))

	idpHandler := internalsml.InterceptMiddleware(inspector, tamperConfig, p.logger, p.IDP)
	ssoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sso/") {
			p.rewriteSSOPath(r)
		}
		idpHandler.ServeHTTP(w, r)
	})

	// Public: the SAML endpoints only. Anything not listed here 404s rather
	// than falling through to the samlidp mux, which also serves the admin API.
	p.PublicMux.HandleFunc("POST /login", p.handleLogin)
	p.PublicMux.Handle("/login", idpHandler)
	p.PublicMux.Handle("/login/{shortcut}", idpHandler)
	p.PublicMux.Handle("/login/{shortcut}/{suffix}", idpHandler)
	p.PublicMux.Handle("GET /metadata", idpHandler)
	p.PublicMux.Handle("/sso", ssoHandler)
	p.PublicMux.Handle("/sso/", ssoHandler)

	// Admin: the samlidp REST API, unwrapped. The intercept middleware only
	// has SAML exchanges to record, so CRUD calls would be noise in the
	// inspector.
	for _, prefix := range []string{"/users/", "/services/", "/sessions/", "/shortcuts/"} {
		p.AdminMux.Handle(prefix, p.IDP)
	}

	webHandler, err := web.NewWebHandler(p.IDP.Store, p.IDP, p.logger, p.externalUrl, p.cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize web UI: %v", err)
	}
	webHandler.SetInspector(inspector)
	webHandler.SetTamperConfig(tamperConfig)

	metadataXML, err := p.Metadata()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate metadata for dashboard: %v", err)
	}
	webHandler.SetMetadataXML(string(metadataXML))
	webHandler.RegisterRoutes(p.AdminMux)
	webHandler.RegisterInspectorRoutes(p.AdminMux)

	p.AdminMux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
	})

	return inspector, tamperConfig, nil
}

func (p *Plasmid) Serve(ctx context.Context) error {
	p.logger.Info("starting server", "host", p.Host, "port", p.Port, "external_url", p.externalUrl)
	p.logger.Info("starting admin server", "host", p.AdminHost, "port", p.AdminPort, "url", p.adminUrl())

	if _, _, err := p.BuildRoutes(); err != nil {
		return err
	}

	public := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", p.Host, p.Port),
		Handler: p.loggingMiddleware(p.PublicMux),
	}
	admin := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", p.AdminHost, p.AdminPort),
		Handler: p.loggingMiddleware(p.AdminMux),
	}

	// Either listener failing takes the whole process down: a running IdP with
	// no dashboard, or a dashboard with no IdP, is not a state worth limping on
	// in. The first error wins and the context cancel stops the other server.
	errs := make(chan error, 2)
	serve := func(name string, srv *http.Server) {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- fmt.Errorf("%s server error: %v", name, err)
			return
		}
		errs <- nil
	}

	// runCtx also fires when one listener dies on its own, so the surviving
	// one is torn down instead of holding the process open.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-runCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		p.logger.Info("shutting down server")
		_ = public.Shutdown(shutdownCtx)
		_ = admin.Shutdown(shutdownCtx)
	}()

	go serve("public", public)
	go serve("admin", admin)

	var firstErr error
	for range 2 {
		if err := <-errs; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

func (p *Plasmid) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("user")
	password := r.PostForm.Get("password")
	if username == "" || password == "" {
		p.IDP.ServeHTTP(w, r)
		return
	}

	var user samlidp.User
	if err := p.IDP.Store.Get("/users/"+username, &user); err != nil {
		p.IDP.ServeHTTP(w, r)
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
		p.IDP.ServeHTTP(w, r)
		return
	}

	session := &saml.Session{
		ID:                    hex.EncodeToString(randomBytes(32)),
		NameID:                user.Email,
		CreateTime:            saml.TimeNow(),
		ExpireTime:            saml.TimeNow().Add(time.Hour),
		Index:                 hex.EncodeToString(randomBytes(32)),
		UserName:              user.Name,
		Groups:                user.Groups,
		UserEmail:             user.Email,
		UserCommonName:        user.CommonName,
		UserSurname:           user.Surname,
		UserGivenName:         user.GivenName,
		UserScopedAffiliation: user.ScopedAffiliation,
	}
	if err := p.IDP.Store.Put("/sessions/"+session.ID, session); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		Path:     "/",
	})

	if samlReq := r.PostForm.Get("SAMLRequest"); samlReq != "" {
		// The login form carries the request in POST-binding format (plain
		// base64 of the raw XML), but GET /sso decodes the redirect binding
		// (deflate, then base64), so recompress before building the URL.
		encodedReq, err := deflateBase64(samlReq)
		if err != nil {
			p.logger.Error("failed to recompress SAMLRequest for redirect", "error", err)
			encodedReq = samlReq
		}
		redirectURL := "/sso?SAMLRequest=" + url.QueryEscape(encodedReq)
		if relayState := r.PostForm.Get("RelayState"); relayState != "" {
			redirectURL += "&RelayState=" + url.QueryEscape(relayState)
		}
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if referer := r.Referer(); referer != "" {
		if u, err := url.Parse(referer); err == nil && strings.HasPrefix(u.Path, "/login/") {
			http.Redirect(w, r, u.Path, http.StatusSeeOther)
			return
		}
	}

	// A bare login with no SAML context has nowhere to go on this listener:
	// the dashboard lives on the admin one, so send the operator there.
	http.Redirect(w, r, p.adminUrl()+"/ui/", http.StatusSeeOther)
}

// deflateBase64 converts a POST-binding SAMLRequest (plain base64 of the raw
// XML) into the redirect-binding encoding (raw deflate, then base64) that
// GET /sso expects.
func deflateBase64(samlRequestB64 string) (string, error) {
	rawXML, err := base64.StdEncoding.DecodeString(samlRequestB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode SAMLRequest: %v", err)
	}
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("failed to create flate writer: %v", err)
	}
	if _, err := writer.Write(rawXML); err != nil {
		return "", fmt.Errorf("failed to compress SAMLRequest: %v", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to finalize compressed SAMLRequest: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func patchDestination(xmlContent, newDest string) string {
	const prefix = `Destination="`
	idx := strings.Index(xmlContent, prefix)
	if idx < 0 {
		return xmlContent
	}
	start := idx + len(prefix)
	end := strings.Index(xmlContent[start:], `"`)
	if end < 0 {
		return xmlContent
	}
	return xmlContent[:start] + newDest + xmlContent[start+end:]
}

func (p *Plasmid) rewriteSSOPath(r *http.Request) {
	expectedDest := p.IDP.IDP.SSOURL.String()
	p.logger.Debug("rewriting SSO path", "original", r.URL.Path, "expected_dest", expectedDest)

	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		samlReq := q.Get("SAMLRequest")
		if samlReq == "" {
			break
		}
		compressed, err := base64.StdEncoding.DecodeString(samlReq)
		if err != nil {
			break
		}
		reader := flate.NewReader(bytes.NewReader(compressed))
		xmlBytes, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			break
		}
		patched := patchDestination(string(xmlBytes), expectedDest)
		if patched == string(xmlBytes) {
			break
		}
		var buf bytes.Buffer
		writer, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		_, _ = writer.Write([]byte(patched))
		writer.Close()
		q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
		r.URL.RawQuery = q.Encode()
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			break
		}
		samlReq := r.PostForm.Get("SAMLRequest")
		if samlReq == "" {
			break
		}
		xmlBytes, err := base64.StdEncoding.DecodeString(samlReq)
		if err != nil {
			break
		}
		patched := patchDestination(string(xmlBytes), expectedDest)
		if patched == string(xmlBytes) {
			break
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(patched))
		r.PostForm.Set("SAMLRequest", encoded)
		r.Form.Set("SAMLRequest", encoded)
	}

	r.URL.Path = "/sso"
}

// Options configures a Plasmid instance. Host/Port bind the public SAML
// listener and AdminHost/AdminPort the admin one; BaseUrl is the external URL
// the public listener is reached on, which becomes the IdP entity ID.
type Options struct {
	Host        string
	Port        int
	AdminHost   string
	AdminPort   int
	BaseUrl     *url.URL
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	Store       samlidp.Store
	Logger      *slog.Logger
}

func New(opts Options) (*Plasmid, error) {
	loginTmpl, err := web.LoginFormTemplate()
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %v", err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:               *opts.BaseUrl,
		Key:               opts.Key,
		Certificate:       opts.Certificate,
		Store:             opts.Store,
		LoginFormTemplate: loginTmpl,
	})
	if err != nil {
		return nil, err
	}

	return &Plasmid{
		Host:        opts.Host,
		Port:        opts.Port,
		AdminHost:   opts.AdminHost,
		AdminPort:   opts.AdminPort,
		IDP:         idpServer,
		PublicMux:   http.NewServeMux(),
		AdminMux:    http.NewServeMux(),
		logger:      opts.Logger,
		externalUrl: opts.BaseUrl.String(),
		cert:        opts.Certificate,
	}, nil
}
