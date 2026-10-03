package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/internal/store"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

const IdpMetadataFile = "idp-metadata.xml"

var serveCmd = &cobra.Command{
	Use:     "serve",
	Aliases: []string{"srv", "s"},
	Short:   "Start SAML IdP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			privKey *rsa.PrivateKey
			cert    *x509.Certificate
			err     error
		)

		keyFile := viper.GetString(config.CertKeyFile)
		_, err = os.Stat(keyFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Info("generating private key", "file", keyFile)
			privKey, err = utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
			if err != nil {
				return err
			}
			if err = utils.WriteKeyToPem(privKey, keyFile); err != nil {
				return err
			}
		} else {
			logr.Info("loading private key", "file", keyFile)
			privKey, err = utils.LoadPrivateKey(keyFile)
			if err != nil {
				return err
			}
		}

		certFile := viper.GetString(config.CertCertificateFile)
		_, err = os.Stat(certFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Info("generating certificate", "file", certFile)
			cert, err = utils.GenerateCertificate(
				privKey,
				viper.GetString(config.CertCaOrg),
				viper.GetString(config.CertCaCountry),
				viper.GetString(config.CertCaState),
				viper.GetString(config.CertCaLocality),
				viper.GetString(config.CertCaAddress),
				viper.GetString(config.CertCaPostcode),
				viper.GetInt(config.CertCaExpYears),
			)
			if err != nil {
				return err
			}
			if err = utils.WriteCertificateToPem(cert, certFile); err != nil {
				return err
			}
		} else {
			logr.Info("loading certificate", "file", certFile)
			cert, err = utils.LoadCertificate(certFile)
			if err != nil {
				return err
			}
		}

		// pre-populate store with default user and optional SP.
		// Wrapped because samlidp.MemoryStore.List is not safe against
		// concurrent writes, and the dashboard polls it while logins run.
		idpStore := store.New(&samlidp.MemoryStore{})

		username := viper.GetString(config.UserUsername)
		logr.Info("registering default user", "username", username)
		password := viper.GetString(config.UserPassword)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %v", err)
		}
		user := samlidp.User{
			Name:              username,
			PlaintextPassword: &password,
			HashedPassword:    hashedPassword,
			Groups:            viper.GetStringSlice(config.UserGroups),
			Email:             viper.GetString(config.UserEmail),
			Surname:           viper.GetString(config.UserLastName),
			GivenName:         viper.GetString(config.UserFirstName),
		}
		if err = idpStore.Put("/users/"+username, &user); err != nil {
			return err
		}

		if metadataSource := viper.GetString(config.SPMetadata); metadataSource != "" {
			metadataBytes, fetchErr := utils.FetchSPMetadata(metadataSource)
			if fetchErr != nil {
				return fetchErr
			}
			services, parseErr := utils.ParseSPServices(viper.GetString(config.SPName), metadataBytes)
			if parseErr != nil {
				return parseErr
			}
			// Written straight to the store rather than through HandlePutService,
			// which does not exist yet; samlidp.New loads them on startup.
			for _, svc := range services {
				logr.Info("registering service provider", "name", svc.Name, "entity_id", svc.Descriptor.EntityID)
				service := samlidp.Service{Name: svc.Name, Metadata: svc.Descriptor}
				if err = idpStore.Put("/services/"+svc.Name, &service); err != nil {
					return err
				}
			}
		}

		// create server
		logr.Info("setting up identity provider")
		baseUrl, err := url.Parse(viper.GetString(config.BaseUrl))
		if err != nil {
			return err
		}
		idp, err := server.New(server.Options{
			Host:                  viper.GetString(config.Host),
			Port:                  viper.GetInt(config.Port),
			AdminHost:             viper.GetString(config.AdminHost),
			AdminPort:             viper.GetInt(config.AdminPort),
			BaseUrl:               baseUrl,
			Key:                   privKey,
			Certificate:           cert,
			Store:                 idpStore,
			Logger:                logr,
			NameIDFormat:          viper.GetString(config.NameIDFormat),
			SignatureMethod:       viper.GetString(config.SignatureMethod),
			IncludeSubjectAddress: viper.GetBool(config.IncludeSubjectAddr),
			SendUnencrypted:       viper.GetBool(config.SendUnencrypted),
		})
		if err != nil {
			return err
		}

		// save metadata
		meta, err := idp.Metadata()
		if err != nil {
			return err
		}
		if err = os.WriteFile(IdpMetadataFile, meta, 0644); err != nil {
			return err
		}
		logr.Info("metadata saved", "file", IdpMetadataFile)

		// start server with graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return idp.Serve(ctx)
	},
}

func init() {
	var f *Flag
	rootCmd.AddCommand(serveCmd)
	f = &Flag{
		Command:     serveCmd,
		Name:        "host",
		ShortHand:   "H",
		Usage:       "host to listen on",
		ConfigField: config.Host,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "port",
		ShortHand:   "P",
		Usage:       "port to listen on",
		ConfigField: config.Port,
	}
	f.BindInt()
	f = &Flag{
		Command:     serveCmd,
		Name:        "url",
		ShortHand:   "u",
		Usage:       "base url exposing idp",
		ConfigField: config.BaseUrl,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "nameid-format",
		Usage:       "NameID format to put in assertions",
		ConfigField: config.NameIDFormat,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "send-unencrypted",
		Usage:       "send assertions signed but unencrypted from startup, so they are readable in the inspector",
		ConfigField: config.SendUnencrypted,
	}
	f.BindBool()
	f = &Flag{
		Command:     serveCmd,
		Name:        "include-subject-address",
		Usage:       "include the client address in SubjectConfirmationData and SubjectLocality",
		ConfigField: config.IncludeSubjectAddr,
	}
	f.BindBool()
	f = &Flag{
		Command:     serveCmd,
		Name:        "signature-method",
		Usage:       "XML signature algorithm to sign assertions and responses with",
		ConfigField: config.SignatureMethod,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "admin-host",
		Usage:       "host to listen on for the dashboard and admin api",
		ConfigField: config.AdminHost,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "admin-port",
		Usage:       "port to listen on for the dashboard and admin api",
		ConfigField: config.AdminPort,
	}
	f.BindInt()
}
