package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/viper"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const StartupDelay = 2 * time.Second
const IdpMetadataFile = "plasmid-metadata.xml"

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:     "serve",
	Aliases: []string{"srv", "s"},
	Short:   "Start SAML IdP server",
	Run: func(cmd *cobra.Command, args []string) {
		var (
			privKey *rsa.PrivateKey
			cert    *x509.Certificate
			err     error
		)

		// load or generate private key
		keyFile := viper.GetString(config.CertKeyFile)
		_, err = os.Stat(keyFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Printf("private key file '%s' not found, generating one", keyFile)
			privKey, err = utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
			handleError(err)
			err = utils.WriteKeyToPem(privKey, keyFile)
			handleError(err)
		} else {
			logr.Printf("loading private key: %s", keyFile)
			privKey, err = utils.LoadPrivateKey(keyFile)
			handleError(err)
		}

		// load or generate certificate
		certFile := viper.GetString(config.CertCertificateFile)
		_, err = os.Stat(certFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Printf("certificate file '%s' not found, generating one", certFile)
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
			handleError(err)
			err = utils.WriteCertificateToPem(cert, certFile)
			handleError(err)
		} else {
			logr.Printf("loading certificate: %s", certFile)
			cert, err = utils.LoadCertificate(certFile)
			handleError(err)
		}

		// prepare idp server
		logr.Println("setting up identity provider server")
		baseUrl, err := url.Parse(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf("invalid base URL '%s': %v", baseUrl, err)
		}
		idp, err := server.New(
			viper.GetString(config.Host),
			viper.GetInt(config.Port),
			baseUrl,
			privKey,
			cert,
		)
		handleError(err)

		// save idp metadata to disk
		meta, err := idp.Metadata()
		handleError(err)
		err = os.WriteFile(IdpMetadataFile, meta, 0644)
		if err != nil {
			logr.Fatalf("failed to write identity provider metadata file: %v", err)
		} else {
			logr.Println("identity provider metadata saved to", IdpMetadataFile)
		}

		// register user and service provider after the idp has started
		go func() {
			time.Sleep(StartupDelay)
			// create plasmid client
			c, err := client.New(viper.GetString(config.BaseUrl))
			handleError(err)
			// create new user
			username := viper.GetString(config.UserUsername)
			logr.Printf("registering new user '%s'", username)
			password := viper.GetString(config.UserPassword)
			err = c.UserAdd(&samlidp.User{
				Name:              username,
				PlaintextPassword: &password,
				Groups:            viper.GetStringSlice(config.UserGroups),
				Email:             viper.GetString(config.UserEmail),
				Surname:           viper.GetString(config.UserLastName),
				GivenName:         viper.GetString(config.UserFirstName),
			})
			handleError(err)
			if viper.GetString(config.SPMetadata) != "" {
				// register service provider
				spName := viper.GetString(config.SPName)
				logr.Printf("registering service provider '%s'", spName)
				err = c.ServiceAdd(
					spName,
					viper.GetString(config.SPMetadata),
				)
				handleError(err)
			}
		}()
		err = idp.Serve()
		handleError(err)
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
