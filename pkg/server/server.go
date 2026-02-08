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
	IDP         *samlidp.Server
	Mux         *http.ServeMux
	logger      *slog.Logger
	externalUrl string
	cert        *x509.Certificate
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

func (p *Plasmid) Serve(ctx context.Context) error {
	p.logger.Info("starting server", "host", p.Host, "port", p.Port, "external_url", p.externalUrl)

	inspector := internalsml.NewInspector(100)
	tamperConfig := internalsml.NewTamperConfig()

	p.IDP.IDP.AssertionMaker = internalsml.TamperableAssertionMaker{Config: tamperConfig}

	webHandler, err := web.NewWebHandler(p.IDP.Store, p.IDP, p.logger, p.externalUrl, p.cert)
	if err != nil {
		return fmt.Errorf("failed to initialize web UI: %v", err)
	}
	webHandler.SetInspector(inspector)
	webHandler.SetTamperConfig(tamperConfig)

	metadataXML, err := p.Metadata()
	if err != nil {
		return fmt.Errorf("failed to generate metadata for dashboard: %v", err)
	}
	webHandler.SetMetadataXML(string(metadataXML))
	webHandler.RegisterRoutes(p.Mux)
	webHandler.RegisterInspectorRoutes(p.Mux)

	p.Mux.HandleFunc("POST /login", p.handleLogin)

	idpHandler := internalsml.InterceptMiddleware(inspector, p.logger, p.IDP)
	p.Mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sso/") {
			p.rewriteSSOPath(r)
		}
		idpHandler.ServeHTTP(w, r)
	}))

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", p.Host, p.Port),
		Handler: p.loggingMiddleware(p.Mux),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.logger.Info("shutting down server")
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %v", err)
	}
	return nil
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
		Secure:   r.URL.Scheme == "https",
		Path:     "/",
	})

	if samlReq := r.PostForm.Get("SAMLRequest"); samlReq != "" {
		redirectURL := "/sso?SAMLRequest=" + url.QueryEscape(samlReq)
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

	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
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

func New(host string, port int, baseUrl *url.URL, privKey *rsa.PrivateKey, cert *x509.Certificate, store samlidp.Store, logger *slog.Logger) (*Plasmid, error) {
	loginTmpl, err := web.LoginFormTemplate()
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %v", err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:                *baseUrl,
		Key:                privKey,
		Certificate:        cert,
		Store:              store,
		LoginFormTemplate:  loginTmpl,
	})
	if err != nil {
		return nil, err
	}

	return &Plasmid{
		Host:        host,
		Port:        port,
		IDP:         idpServer,
		Mux:         http.NewServeMux(),
		logger:      logger,
		externalUrl: baseUrl.String(),
		cert:        cert,
	}, nil
}
