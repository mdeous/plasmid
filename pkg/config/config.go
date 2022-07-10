package config

import (
	"fmt"
	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// HOME MADE

func getEnv(varName string, defaultVal string) string {
	value, exists := os.LookupEnv(varName)
	if !exists {
		return defaultVal
	}
	return value
}

func Load(filename string) (*Config, error) {
	var (
		cfg *Config
		err error
	)

	if filename != "" {
		configContent, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(configContent, cfg)
		if err != nil {
			return nil, err
		}
		err = defaults.Set(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		cfg = &Config{}
	}

	// IdP config
	listenHost := getEnv("IDP_LISTEN_HOST", "127.0.0.1")
	listenPortStr := getEnv("IDP_LISTEN_PORT", "8000")
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen port '%s': %v", listenPortStr, err)
	}
	var baseUrl *url.URL
	baseUrlStr := getEnv("IDP_BASE_URL", "")
	if baseUrlStr == "" {
		baseUrlStr = fmt.Sprintf("http://%s:%d", listenHost, listenPort)
	}
	baseUrl, err = url.Parse(baseUrlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base url '%s': %v", baseUrlStr, err)
	}
	cfg.Host = listenHost
	cfg.Port = listenPort
	cfg.BaseUrl = *baseUrl

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
	ca := Certificate{
		CAOrganization: getEnv("IDP_CA_ORGANIZATION", "Example Org"),
		CACountry:      getEnv("IDP_CA_COUNTRY", "FR"),
		CAProvince:     getEnv("IDP_CA_PROVINCE", ""),
		CALocality:     getEnv("IDP_CA_LOCALITY", "Paris"),
		CAAddress:      getEnv("IDP_CA_ADDRESS", ""),
		CAPostCode:     getEnv("IDP_CA_POSTCODE", ""),
		CAExpiration:   caExp,
		CertFile:       getEnv("IDP_CERT_FILE", ""),
		KeyFile:        getEnv("IDP_KEY_FILE", ""),
		KeySize:        keySize,
	}
	cfg.CA = ca

	// user config
	userEmailStr := getEnv("IDP_USER_EMAIL", "admin@example.com")
	userEmail, err := mail.ParseAddress(userEmailStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user email '%s': %v", userEmailStr, err)
	}
	user := User{
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
	spMetadata := getEnv("IDP_SP_METADATA", "")
	if spMetadata != "" {
		spMetadataParsed, err := url.Parse(spMetadata)
		if err != nil {
			return nil, fmt.Errorf("invalid service provider metadata url '%s': %v", spMetadata, err)
		}
		spMetadata = spMetadataParsed.String()
	}
	sp := ServiceProvider{
		Name:     getEnv("IDP_SP_NAME", "serviceprovider"),
		Metadata: spMetadata,
	}
	cfg.ServiceProvider = sp

	return cfg, nil
}
