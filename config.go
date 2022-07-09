package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type SPConfig struct {
	Name     string
	Metadata string
}

type IdpCertConfig struct {
	CAOrganization string
	CACountry      string
	CAProvince     string
	CALocality     string
	CAAddress      string
	CAPostCode     string
	CAExpiration   int
	KeySize        int
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
	CA              *IdpCertConfig
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
	caExpStr := getEnv("IDP_CA_EXPIRATION", "1")
	caExp, err := strconv.Atoi(caExpStr)
	if err != nil || caExp < 1 {
		return nil, fmt.Errorf("invalid CA expiration years '%s': %v", caExpStr, err)
	}
	keySizeStr := getEnv("IDP_KEY_SIZE", "2048")
	keySize, err := strconv.Atoi(keySizeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid key size '%s': %v", keySizeStr, err)
	}
	ca := &IdpCertConfig{
		CAOrganization: getEnv("IDP_CA_ORGANIZATION", "Example Org"),
		CACountry:      getEnv("IDP_CA_COUNTRY", "FR"),
		CAProvince:     getEnv("IDP_CA_PROVINCE", ""),
		CALocality:     getEnv("IDP_CA_LOCALITY", "Paris"),
		CAAddress:      getEnv("IDP_CA_ADDRESS", ""),
		CAPostCode:     getEnv("IDP_CA_POSTCODE", ""),
		CAExpiration:   caExp,
		KeySize:        keySize,
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
