package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/mdeous/plasmid/pkg/config"
	"io/ioutil"
	"math/big"
	"time"
)

func readPemFile(path string) ([]byte, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, _ := pem.Decode(pemBytes)
	return decoded.Bytes, nil
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privKeyBytes, err := readPemFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load private key from '%s': %v", filename, err)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
	return privKey, nil
}

func LoadCertificate(filename string) (*x509.Certificate, error) {
	certBytes, err := readPemFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate from '%s': %v", filename, err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %v", err)
	}
	return cert, nil
}

func GeneratePrivateKey(cfg *config.Certificate) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}
	return privKey, nil
}

func GenerateCertificate(cfg *config.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	// generate CA certificate
	ca := &x509.Certificate{
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

	// generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %v", err)
	}
	return cert, nil
}
