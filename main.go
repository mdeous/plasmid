package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zenazn/goji"
	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

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

func generateKeys() (*IdpKeys, error) {
	// generate CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{getEnv("IDP_CA_NAME", "Example Org")},
			Country:       []string{getEnv("IDP_CA_COUNTRY", "FR")},
			Province:      []string{getEnv("IDP_CA_PROVINCE", "")},
			Locality:      []string{getEnv("IDP_CA_LOCALITY", "Paris")},
			StreetAddress: []string{getEnv("IDP_CA_ADDRESS", "")},
			PostalCode:    []string{getEnv("IDP_CA_POSTCODE", "")},
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
	logr := logger.DefaultLogger

	logr.Println("generating identity provider keys")
	keys, err := generateKeys()
	if err != nil {
		logr.Fatalln(err.Error())
	}

	logr.Println("preparing identity provider")
	baseUrl, _ := url.Parse("http://127.0.0.1:8000")
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseUrl,
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

	username := getEnv("IDP_USER_NAME", "admin")
	password := getEnv("IDP_USER_PASSWORD", "Password123")
	groups := strings.Split(getEnv("IDP_USER_GROUPS", "Administrators,Users"), ",")
	fullName := getEnv("IDP_USER_FULLNAME", "Admin User")
	givenName := getEnv("IDP_USER_GIVENNAME", "Admin")
	surname := getEnv("IDP_USER_SURNAME", "User")
	email := getEnv("IDP_USER_EMAIL", "admin@example.com")

	logr.Printf("creating new user: %s", username)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logr.Fatalf("unable to hash user password: %v", err)
	}
	err = idpServer.Store.Put("/users/"+username, samlidp.User{
		Name:           username,
		HashedPassword: hashedPassword,
		Groups:         groups,
		Email:          email,
		CommonName:     fullName,
		Surname:        surname,
		GivenName:      givenName,
	})
	if err != nil {
		logr.Fatalf(err.Error())
	}

	logr.Println("starting identity provider server")
	goji.Handle("/*", idpServer)
	goji.Serve()
}
