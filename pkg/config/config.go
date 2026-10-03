package config

import (
	"strings"

	"github.com/spf13/viper"
)

const (
	EnvPrefix   = "IDP"
	DefaultFile = "plasmid.yaml"

	Host                = "host"
	Port                = "port"
	BaseUrl             = "base_url"
	AdminHost           = "admin_host"
	AdminPort           = "admin_port"
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
	NameIDFormat        = "nameid_format"
	SignatureMethod     = "signature_method"
	IncludeSubjectAddr  = "include_subject_address"
)

var DefaultValues = map[string]any{
	Host:                "127.0.0.1",
	Port:                8000,
	BaseUrl:             "http://127.0.0.1:8000",
	AdminHost:           "127.0.0.1",
	AdminPort:           8001,
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
	// samlidp never sets a NameID format, which leaves crewjam/saml emitting
	// transient. Practically every real SP identifies users by email address,
	// so transient makes a first login attempt against a new SP fail for a
	// reason unrelated to whatever is being tested.
	NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	// crewjam/saml falls back to RSA-SHA1, which modern SPs reject. This is
	// dsig.RSASHA256SignatureMethod, spelled out so this package stays free of
	// the signing library.
	SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	// crewjam/saml fills the subject addresses from RemoteAddr, which is
	// "host:port" and behind a tunnel is loopback. A conforming SP rejects the
	// assertion over it, so leave them out unless asked for.
	IncludeSubjectAddr: false,
}

func LoadFile(filePath string) error {
	viper.SetConfigFile(filePath)
	return viper.ReadInConfig()
}

func Init() {
	// setup configuration via environment variables
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// set default values
	for k, v := range DefaultValues {
		viper.SetDefault(k, v)
	}
}
