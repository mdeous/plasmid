package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type PemType string

const CertificateType PemType = "CERTIFICATE"
const PrivateKeyType PemType = "RSA PRIVATE KEY"

func readPemFile(path string) ([]byte, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, _ := pem.Decode(pemBytes)
	return decoded.Bytes, nil
}

func writePemFile(path string, content []byte, pemType PemType) error {
	var err error
	// encode content to PEM
	pemBytes := new(bytes.Buffer)
	err = pem.Encode(pemBytes, &pem.Block{
		Type:  string(pemType),
		Bytes: content,
	})
	if err != nil {
		return err
	}
	// write PEM file to disk
	err = os.WriteFile(path, pemBytes.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func WriteKeyToPem(key *rsa.PrivateKey, path string) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return writePemFile(path, keyBytes, PrivateKeyType)
}

func WriteCertificateToPem(cert *x509.Certificate, path string) error {
	return writePemFile(path, cert.Raw, CertificateType)
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

func GeneratePrivateKey(keySize int) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}
	return privKey, nil
}

func GenerateCertificate(
	key *rsa.PrivateKey,
	orgName string,
	country string,
	state string,
	locality string,
	address string,
	postCode string,
	expirationYears int,
) (*x509.Certificate, error) {
	// generate CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization:  []string{orgName},
			Country:       []string{country},
			Province:      []string{state},
			Locality:      []string{locality},
			StreetAddress: []string{address},
			PostalCode:    []string{postCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(expirationYears, 0, 0),
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
