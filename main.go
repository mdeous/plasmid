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
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zenazn/goji"
	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

var logr = logger.DefaultLogger

type SPConfig struct {
	Name     string
	Metadata string
}

type IdpCAConfig struct {
	Organization string
	Country      string
	Province     string
	Locality     string
	Address      string
	PostCode     string
}

type IdpUserConfig struct {
	UserName  string
	Password  string
	Groups    []string
	FullName  string
	GivenName string
	Surname   string
	Email     string
}

type IdpConfig struct {
	BaseUrl         *url.URL
	CA              *IdpCAConfig
	User            *IdpUserConfig
	ServiceProvider *SPConfig
}

type IdpKeys struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func getEnv(varName string, defaultVal string) string {
	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultVal
	}
	return value
}

func getConfig() (*IdpConfig, error) {
	var err error

	// IdP config
	baseUrlStr := getEnv("IDP_BASE_URL", "http://127.0.0.1:8000")
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base url '%s': %v", baseUrlStr, err)
	}
	cfg := &IdpConfig{
		BaseUrl: baseUrl,
	}

	// CA cert config
	ca := &IdpCAConfig{
		Organization: getEnv("IDP_CA_ORGANIZATION", "Example Org"),
		Country:      getEnv("IDP_CA_COUNTRY", "FR"),
		Province:     getEnv("IDP_CA_PROVINCE", ""),
		Locality:     getEnv("IDP_CA_LOCALITY", "Paris"),
		Address:      getEnv("IDP_CA_ADDRESS", ""),
		PostCode:     getEnv("IDP_CA_POSTCODE", ""),
	}
	cfg.CA = ca

	// user config
	userEmailStr := getEnv("IDP_USER_EMAIL", "admin@example.com")
	userEmail, err := mail.ParseAddress(userEmailStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user email '%s': %v", userEmailStr, err)
	}
	user := &IdpUserConfig{
		UserName:  getEnv("IDP_USER_NAME", "admin"),
		Password:  getEnv("IDP_USER_PASSWORD", "Password123"),
		Groups:    strings.Split(getEnv("IDP_USER_GROUPS", "Administrators,Users"), ","),
		FullName:  getEnv("IDP_USER_FULLNAME", "Admin User"),
		GivenName: getEnv("IDP_USER_GIVENNAME", "Admin"),
		Surname:   getEnv("IDP_USER_SURNAME", "User"),
		Email:     userEmail.Address,
	}
	cfg.User = user

	// service provider config
	var spMetadata *url.URL
	spMetadataStr := getEnv("IDP_SP_METADATA", "")
	if spMetadataStr != "" {
		spMetadata, err = url.Parse(spMetadataStr)
		if err != nil {
			return nil, fmt.Errorf("invalid service provider metadata url '%s': %v", spMetadataStr, err)
		}
	}
	sp := &SPConfig{
		Name:     getEnv("IDP_SP_NAME", "serviceprovider"),
		Metadata: spMetadata.String(),
	}
	cfg.ServiceProvider = sp

	return cfg, nil
}

func generateKeys(cfg *IdpCAConfig) (*IdpKeys, error) {
	// generate CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization:  []string{cfg.Organization},
			Country:       []string{cfg.Country},
			Province:      []string{cfg.Province},
			Locality:      []string{cfg.Locality},
			StreetAddress: []string{cfg.Address},
			PostalCode:    []string{cfg.PostCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	// generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
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
	logr.Printf("identity provider metadata:\n%s", metaXml)

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
		go func() {
			time.Sleep(5 * time.Second)
			logr.Printf("registering service provider: %s", cfg.ServiceProvider.Name)

			// read saml metadata from url
			samlResp, err := http.Get(cfg.ServiceProvider.Metadata)
			if err != nil {
				logr.Fatalf("unable to fetch service provider metadata: %s", err)
			}
			if samlResp.StatusCode != http.StatusOK {
				data, _ := ioutil.ReadAll(samlResp.Body)
				logr.Fatalf("error while fetching service provider metadata: %d: %s", samlResp.StatusCode, data)
			}

			// guess which address we're running on
			req, err := http.NewRequest("PUT", cfg.BaseUrl.String()+"/services/"+cfg.ServiceProvider.Name, samlResp.Body)
			if err != nil {
				logr.Fatalf("new request: %s", err)
			}

			// post to self because memorystore only works for users
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				logr.Fatalf("send request: %s", err)
			}

			if resp.StatusCode != http.StatusNoContent {
				data, _ := ioutil.ReadAll(resp.Body)
				logr.Fatalf("status not ok: %d: %s", resp.StatusCode, data)
			}

			_ = resp.Body.Close()
		}()
	}

	logr.Println("starting identity provider server")
	goji.Handle("/*", idpServer)
	goji.Serve()
}
