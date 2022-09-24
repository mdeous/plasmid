package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/viper"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const RegisterSPDelay = 2 * time.Second
const IdpMetadataFile = "idp-metadata.xml"

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start SAML IdP server",
	Run: func(cmd *cobra.Command, args []string) {
		var (
			privKey *rsa.PrivateKey
			cert    *x509.Certificate
			err     error
		)

		// load or generate identity provider keys
		if viper.GetString(config.CertKeyFile) != "" {
			privKey, err = utils.LoadPrivateKey(viper.GetString(config.CertKeyFile))
			handleError(err)
		} else {
			privKey, err = utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
			handleError(err)
		}
		if viper.GetString(config.CertCertificateFile) != "" {
			cert, err = utils.LoadCertificate(viper.GetString(config.CertCertificateFile))
			handleError(err)
		} else {
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
		}

		// prepare idp server
		logr.Println("setting up identity provider server")
		baseUrl, err := url.Parse(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf("invalid base URL '%s': %v", viper.GetString(config.BaseUrl), err)
		}
		idp, err := server.New(
			viper.GetString(config.Host),
			viper.GetInt(config.Port),
			baseUrl,
			privKey,
			cert,
		)
		handleError(err)

		// register user
		err = idp.RegisterUser(
			viper.GetString(config.UserUsername),
			viper.GetString(config.UserPassword),
			viper.GetStringSlice(config.UserGroups),
			viper.GetString(config.UserEmail),
			viper.GetString(config.UserFirstName),
			viper.GetString(config.UserLastName),
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

		// register service provider after the idp has started
		if viper.GetString(config.SPMetadata) != "" {
			go func() {
				time.Sleep(RegisterSPDelay)
				// TODO: allow to pass SP metadata as a file
				err = idp.RegisterServiceProvider(
					viper.GetString(config.SPName),
					viper.GetString(config.SPMetadata),
				)
				handleError(err)
			}()
		}

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
