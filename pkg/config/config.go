package config

import (
	"errors"
	"github.com/spf13/viper"
	"strings"
)

const (
	EnvPrefix   = "IDP"
	FileFormat  = "yaml"
	DefaultFile = "plasmid.yaml"
	DefaultPath = "."

	Host                = "host"
	Port                = "port"
	BaseUrl             = "base_url"
	CertCaOrg           = "cert.ca_org"
	CertCaCountry       = "cert.ca_country"
	CertCaState         = "cert.ca_state"
	CertCaLocality      = "cert.ca_locality"
	CertCaAddress       = "cert.ca_address"
	CertCaPostcode      = "cert.ca_postcode"
	CertCaExpYears      = "cert.ca_exp_years"
	CertCertificateFile = "cert.certificate_file"
	CertKeyFile         = "cert.key_file"
	CertKeySize         = "cert.key_size"
	UserUsername        = "user.username"
	UserPassword        = "user.password"
	UserFirstName       = "user.given_name"
	UserLastName        = "user.surname"
	UserEmail           = "user.email"
	UserGroups          = "user.groups"
	SPName              = "sp.name"
	SPMetadata          = "sp.metadata"
)

var DefaultValues = map[string]interface{}{
	Host:                "127.0.0.1",
	Port:                8000,
	BaseUrl:             "http://127.0.0.1:8000",
	CertCaOrg:           "Example Org",
	CertCaCountry:       "FR",
	CertCaState:         "Ile de France",
	CertCaLocality:      "Paris",
	CertCaPostcode:      "75001",
	CertCaExpYears:      1,
	CertKeySize:         2048,
	CertCertificateFile: "plasmid-cert.pem",
	CertKeyFile:         "plasmid-key.pem",
	UserUsername:        "admin",
	UserPassword:        "Password123",
	UserFirstName:       "Admin",
	UserLastName:        "User",
	UserEmail:           "admin@example.com",
	UserGroups:          []string{"Administrators", "Users"},
}

func Init() {
	// load from file if it exists
	viper.SetConfigName(DefaultFile)
	viper.SetConfigType(FileFormat)
	viper.AddConfigPath(DefaultPath)
	err := viper.ReadInConfig()
	if err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			panic(err)
		}
	}

	// setup configuration via environment variables
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// set default values
	for k, v := range DefaultValues {
		viper.SetDefault(k, v)
	}
}
