package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/zenazn/goji"
	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

var logr = logger.DefaultLogger

func generateKeys(cfg *IdpCertConfig) (*IdpKeys, error) {
	var (
		ca      *x509.Certificate
		privKey *rsa.PrivateKey
		cert    *x509.Certificate
		err     error
	)

	// generate CA
	ca = &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization:  []string{cfg.CAOrganization},
			Country:       []string{cfg.CACountry},
			Province:      []string{cfg.CAProvince},
			Locality:      []string{cfg.CALocality},
			StreetAddress: []string{cfg.CAAddress},
			PostalCode:    []string{cfg.CAPostCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(cfg.CAExpiration, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate private key
	privKey, err = rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	// generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %v", err)
	}

	// build keys struct
	keys := &IdpKeys{
		Certificate: cert,
		PrivateKey:  privKey,
	}
	return keys, nil
}

func registerServiceProvider(cfg *IdpConfig) {
	time.Sleep(2 * time.Second)

	// fetch service provider metadata
	logr.Printf("fetching service provider metadata from '%s'", cfg.ServiceProvider.Metadata)
	samlResp, err := http.Get(cfg.ServiceProvider.Metadata)
	if err != nil {
		logr.Fatalf("unable to fetch service provider metadata: %s", err)
	}
	if samlResp.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(samlResp.Body)
		logr.Fatalf("error while fetching service provider metadata: %d: %s", samlResp.StatusCode, data)
	}

	// register service provider
	logr.Printf("registering service provider '%s'", cfg.ServiceProvider.Name)
	req, err := http.NewRequest("PUT", cfg.BaseUrl.String()+"/services/"+cfg.ServiceProvider.Name, samlResp.Body)
	if err != nil {
		logr.Fatalf("unable to create registration request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logr.Fatalf("error while registering service provider: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		data, _ := ioutil.ReadAll(resp.Body)
		logr.Fatalf("unexpected response status code (%d): %s", resp.StatusCode, data)
	}

	_ = resp.Body.Close()
}

func main() {
	logr.Println("loading configuration values from environment")
	cfg, err := getConfig()
	if err != nil {
		logr.Fatalf("unable to load configuration: %v", err)
	}

	logr.Println("generating identity provider keys")
	keys, err := generateKeys(cfg.CA)
	if err != nil {
		logr.Fatalln(err.Error())
	}

	logr.Println("preparing identity provider")
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *cfg.BaseUrl,
		Key:         keys.PrivateKey,
		Logger:      logr,
		Certificate: keys.Certificate,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf(err.Error())
	}
	metaXml, err := xml.MarshalIndent(idpServer.IDP.Metadata(), "", "    ")
	if err != nil {
		logr.Fatalf("unable to marshal metadata: %v", err)
	}
	logr.Printf("identity provider metadata available at: %s/metadata", cfg.BaseUrl.String())
	logr.Printf("metadata content:\n%s", metaXml)

	logr.Printf("creating new user: %s", cfg.User.UserName)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.User.Password), bcrypt.DefaultCost)
	if err != nil {
		logr.Fatalf("unable to hash user password: %v", err)
	}
	err = idpServer.Store.Put("/users/"+cfg.User.UserName, samlidp.User{
		Name:           cfg.User.UserName,
		HashedPassword: hashedPassword,
		Groups:         cfg.User.Groups,
		Email:          cfg.User.Email,
		CommonName:     cfg.User.FullName,
		Surname:        cfg.User.Surname,
		GivenName:      cfg.User.GivenName,
	})
	if err != nil {
		logr.Fatalf(err.Error())
	}

	// wait for startup and register service provider
	if cfg.ServiceProvider.Metadata != "" {
		go registerServiceProvider(cfg)
	}

	logr.Println("starting identity provider server")
	goji.Handle("/*", idpServer)
	goji.Serve()
}
