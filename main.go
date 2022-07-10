package main

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"time"

	"github.com/crewjam/saml/logger"
)

const RegisterSPDelay = 2 * time.Second

var logr = logger.DefaultLogger

func main() {
	var (
		privKey *rsa.PrivateKey
		cert    *x509.Certificate
		err     error
	)

	// load configuration from environment variables
	logr.Println("reading configuration values")
	cfg, err := config.Load("")
	if err != nil {
		logr.Fatalf("unable to load configuration: %v", err)
	}

	// load or generate identity provider keys

	if cfg.CA.KeyFile != "" {
		privKey, err = utils.LoadPrivateKey(cfg.CA.KeyFile)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	} else {
		privKey, err = utils.GeneratePrivateKey(&cfg.CA)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	}
	if cfg.CA.CertFile != "" {
		cert, err = utils.LoadCertificate(cfg.CA.CertFile)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	} else {
		cert, err = utils.GenerateCertificate(&cfg.CA, privKey)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	}

	// prepare idp server
	logr.Println("setting up identity provider server")
	idp, err := server.New(cfg.Host, cfg.Port, &cfg.BaseUrl, privKey, cert)
	if err != nil {
		logr.Fatalf(err.Error())
	}

	// register user
	err = idp.RegisterUser(&cfg.User)
	if err != nil {
		logr.Fatalf(err.Error())
	}

	if cfg.ServiceProvider.Metadata != "" {
		go func() {
			time.Sleep(RegisterSPDelay)
			err = idp.RegisterServiceProvider(cfg.ServiceProvider.Name, cfg.ServiceProvider.Metadata)
			if err != nil {
				logr.Fatalf(err.Error())
			}
		}()
	}

	err = idp.Serve()
	if err != nil {
		logr.Fatalf(err.Error())
	}
}
