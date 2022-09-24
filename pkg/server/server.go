package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	goji "goji.io"
	"goji.io/pat"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Plasmid struct {
	Host        string
	Port        int
	IDP         *samlidp.Server
	logger      *log.Logger
	internalUrl string
	externalUrl string
	client      *client.PlasmidClient
}

func (p *Plasmid) Metadata() ([]byte, error) {
	metaDescriptor := p.IDP.IDP.Metadata()
	meta, err := xml.MarshalIndent(metaDescriptor, "", " ")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to serialize idp metadata: %v", err)
	}
	return meta, nil
}

func (p *Plasmid) RegisterServiceProvider(spName string, spMetaUrl string) error {
	p.logger.Printf("registering service provider '%s'", spName)
	err := p.client.ServiceAdd(spName, spMetaUrl)
	if err != nil {
		return err
	}
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
		reqUrl := strings.Replace(req.URL.String(), "\n", "", -1)
		reqUrl = strings.Replace(reqUrl, "\r", "", -1)
		p.logger.Printf("%s %s %s", req.RemoteAddr, req.Method, reqUrl)
		handler.ServeHTTP(resp, req)
	}
	return http.HandlerFunc(mw)
}

func (p *Plasmid) Serve() error {
	p.logger.Printf("listening on %s:%d", p.Host, p.Port)
	p.logger.Printf("external url: %s", p.externalUrl)
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

	u := new(url.URL)
	u.Scheme = "http"
	u.Host = fmt.Sprintf("%s:%d", host, port)

	c, err := client.New(u.String())
	if err != nil {
		return nil, err
	}
	plasmid := &Plasmid{
		Host:        host,
		Port:        port,
		IDP:         idpServer,
		logger:      logger.DefaultLogger,
		internalUrl: u.String(),
		externalUrl: baseUrl.String(),
		client:      c,
	}
	return plasmid, nil
}
