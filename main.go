package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"goji.io/pat"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"goji.io"
	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

var logr = logger.DefaultLogger

func readPemFile(path string) ([]byte, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, _ := pem.Decode(pemBytes)
	return decoded.Bytes, nil
}

func generateKeys(cfg *IdpCertConfig) (*IdpKeys, error) {
	var (
		privKeyUntyped any
		ca             *x509.Certificate
		cert           *x509.Certificate
		err            error
	)

	// load or generate private key
	if cfg.KeyFile != "" {
		logr.Printf("loading identity provider private key from %s", cfg.KeyFile)
		privKeyBytes, err := readPemFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load private key from '%s': %v", cfg.KeyFile, err)
		}
		privKeyUntyped, err = x509.ParsePKCS1PrivateKey(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}

	} else {
		logr.Println("generating identity provider private key")
		privKeyUntyped, err = rsa.GenerateKey(rand.Reader, cfg.KeySize)
		if err != nil {
			return nil, fmt.Errorf("unable to generate private key: %v", err)
		}
	}
	var privKey = privKeyUntyped.(*rsa.PrivateKey)

	// load or generate certificate
	if cfg.CertFile != "" {
		logr.Printf("loading identity provider certificate from %s", cfg.CertFile)
		certBytes, err := readPemFile(cfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load certificate from '%s': %v", cfg.CertFile, err)
		}
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
	} else {
		logr.Println("generating identity provider certificate authority")
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
		logr.Println("generating identity provider certificate")
		certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
		if err != nil {
			return nil, fmt.Errorf("unable to generate certificate: %v", err)
		}
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
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

func LoggingMiddleware(handler http.Handler) http.Handler {
	mw := func(resp http.ResponseWriter, req *http.Request) {
		logr.Printf("%s %s %s", req.RemoteAddr, req.Method, req.URL.String())
		handler.ServeHTTP(resp, req)
	}
	return http.HandlerFunc(mw)
}

func main() {
	var err error

	logr.Println("loading configuration values from environment")
	cfg, err := getConfig()
	if err != nil {
		logr.Fatalf("unable to load configuration: %v", err)
	}

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
	logr.Printf("identity provider metadata available at: %s/metadata", cfg.BaseUrl.String())

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

	// start server
	logr.Println("starting identity provider server")
	mux := goji.NewMux()
	mux.Use(LoggingMiddleware)
	mux.Handle(pat.New("/*"), idpServer)
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort), mux)
	if err != nil {
		logr.Fatalf("error while starting server: %v", err)
	}
}
