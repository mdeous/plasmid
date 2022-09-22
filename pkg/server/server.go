package server

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	goji "goji.io"
	"goji.io/pat"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

const RegisterSPDelay = 2 * time.Second

type Plasmid struct {
	Host    string
	Port    int
	BaseUrl *url.URL
	IDP     *samlidp.Server
	logger  *log.Logger
}

func (p *Plasmid) RegisterServiceProvider(spName string, spMetaUrl string) error {
	time.Sleep(RegisterSPDelay)

	// fetch service provider metadata
	p.logger.Printf("fetching service provider metadata from '%s'", spMetaUrl)
	samlResp, err := http.Get(spMetaUrl)
	if err != nil {
		return err
	}
	if samlResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(samlResp.Body)
		return fmt.Errorf("error while fetching service provider metadata: %d: %s", samlResp.StatusCode, data)
	}

	// register service provider
	p.logger.Printf("registering service provider '%s'", spName)
	req, err := http.NewRequest("PUT", p.BaseUrl.String()+"/services/"+spName, samlResp.Body)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response status code (%d): %s", resp.StatusCode, data)
	}

	_ = resp.Body.Close()
	return nil
}

func (p *Plasmid) RegisterUser(
	username string,
	password string,
	groups []string,
	email string,
	firstName string,
	lastName string,
) error {
	p.logger.Printf("registering user '%s'", username)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("unable to hash user '%s' password: %v", username, err)
	}
	err = p.IDP.Store.Put("/users/"+username, samlidp.User{
		Name:           username,
		HashedPassword: hashedPassword,
		Groups:         groups,
		Email:          email,
		GivenName:      firstName,
		Surname:        lastName,
		CommonName:     fmt.Sprintf("%s %s", firstName, lastName),
	})
	if err != nil {
		return fmt.Errorf("unable to register user '%s': %v", username, err)
	}
	return nil
}

func (p *Plasmid) LoggingMiddleware(handler http.Handler) http.Handler {
	mw := func(resp http.ResponseWriter, req *http.Request) {
		p.logger.Printf("%s %s %s", req.RemoteAddr, req.Method, req.URL.String())
		handler.ServeHTTP(resp, req)
	}
	return http.HandlerFunc(mw)
}

func (p *Plasmid) Serve() error {
	p.logger.Printf("listening on %s:%d", p.Host, p.Port)
	mux := goji.NewMux()
	mux.Use(p.LoggingMiddleware)
	mux.Handle(pat.New("/*"), p.IDP)
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", p.Host, p.Port), mux)
	if err != nil {
		return fmt.Errorf("error while starting server: %v", err)
	}
	return nil
}

func New(host string, port int, baseUrl *url.URL, privKey *rsa.PrivateKey, cert *x509.Certificate) (*Plasmid, error) {
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseUrl,
		Key:         privKey,
		Logger:      logger.DefaultLogger,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		return nil, err
	}

	plasmid := &Plasmid{
		Host:    host,
		Port:    port,
		BaseUrl: baseUrl,
		IDP:     idpServer,
		logger:  logger.DefaultLogger,
	}
	return plasmid, nil
}
