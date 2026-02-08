package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
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

		// pre-populate store with default user and optional SP
		store := &samlidp.MemoryStore{}

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
		if err = store.Put("/users/"+username, &user); err != nil {
			return err
		}

		if metadataSource := viper.GetString(config.SPMetadata); metadataSource != "" {
			spName := viper.GetString(config.SPName)
			logr.Info("registering service provider", "name", spName)
			metadataBytes, fetchErr := utils.FetchSPMetadata(metadataSource)
			if fetchErr != nil {
				return fetchErr
			}
			var metadata saml.EntityDescriptor
			if err = xml.Unmarshal(metadataBytes, &metadata); err != nil {
				return fmt.Errorf("unable to parse SP metadata: %v", err)
			}
			service := samlidp.Service{Name: spName, Metadata: metadata}
			if err = store.Put("/services/"+spName, &service); err != nil {
				return err
			}
		}

		// create server
		logr.Info("setting up identity provider")
		baseUrl, err := url.Parse(viper.GetString(config.BaseUrl))
		if err != nil {
			return err
		}
		idp, err := server.New(
			viper.GetString(config.Host),
			viper.GetInt(config.Port),
			baseUrl,
			privKey,
			cert,
			store,
			logr,
		)
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
}
