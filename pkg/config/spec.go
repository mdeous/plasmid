package config

import "net/url"

type Config struct {
	Host            string          `yaml:"host" default:"127.0.0.1"`
	Port            int             `yaml:"port" default:"8000"`
	BaseUrl         url.URL         `yaml:"base_url,omitempty"`
	CA              Certificate     `yaml:"ca"`
	User            User            `yaml:"users"`
	ServiceProvider ServiceProvider `yaml:"sp"`
}

type Certificate struct {
	CAOrganization string `yaml:"ca_org" default:"Example Org"`
	CACountry      string `yaml:"ca_country" default:"FR"`
	CAProvince     string `yaml:"ca_province,omitempty"`
	CALocality     string `yaml:"ca_locality" default:"Paris"`
	CAAddress      string `yaml:"ca_address,omitempty"`
	CAPostCode     string `yaml:"ca_postcode,omitempty"`
	CAExpiration   int    `yaml:"ca_exp_years" default:"1"`
	CertFile       string `yaml:"cert_file,omitempty"`
	KeyFile        string `yaml:"key_file,omitempty"`
	KeySize        int    `yaml:"key_size" default:"2048"`
}

type User struct {
	UserName  string   `yaml:"username" default:"admin"`
	Password  string   `yaml:"password" default:"Password123"`
	Groups    []string `yaml:"groups" default:"[\"Administrators\",\"Users\"]"`
	FullName  string   `yaml:"full_name" default:"Admin User"`
	GivenName string   `yaml:"given_name" default:"Admin"`
	Surname   string   `yaml:"surname" default:"User"`
	Email     string   `yaml:"email" default:"admin@example.com"`
}

type ServiceProvider struct {
	Name     string `yaml:"name"`
	Metadata string `yaml:"metadata"`
}
