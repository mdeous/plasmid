package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/crewjam/saml/logger"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/viper"
	"net/url"
	"time"

	"github.com/spf13/cobra"
)

const RegisterSPDelay = 2 * time.Second

var logr = logger.DefaultLogger

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

		// load configuration from environment variables
		logr.Println("reading configuration values")
		err = config.Load()
		if err != nil {
			logr.Fatalf("unable to load configuration: %v", err)
		}

		// load or generate identity provider keys

		if viper.GetString(config.CertKeyFile) != "" {
			privKey, err = utils.LoadPrivateKey(viper.GetString(config.CertKeyFile))
			if err != nil {
				logr.Fatalf(err.Error())
			}
		} else {
			privKey, err = utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
			if err != nil {
				logr.Fatalf(err.Error())
			}
		}
		if viper.GetString(config.CertCertificateFile) != "" {
			cert, err = utils.LoadCertificate(viper.GetString(config.CertCertificateFile))
			if err != nil {
				logr.Fatalf(err.Error())
			}
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
			if err != nil {
				logr.Fatalf(err.Error())
			}
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
		if err != nil {
			logr.Fatalf(err.Error())
		}

		// register user
		err = idp.RegisterUser(
			viper.GetString(config.UserUsername),
			viper.GetString(config.UserPassword),
			viper.GetStringSlice(config.UserGroups),
			viper.GetString(config.UserEmail),
			viper.GetString(config.UserFirstName),
			viper.GetString(config.UserLastName),
		)
		if err != nil {
			logr.Fatalf(err.Error())
		}

		if viper.GetString(config.SPMetadata) != "" {
			go func() {
				time.Sleep(RegisterSPDelay)
				err = idp.RegisterServiceProvider(
					viper.GetString(config.SPName),
					viper.GetString(config.SPMetadata),
				)
				if err != nil {
					logr.Fatalf(err.Error())
				}
			}()
		}

		err = idp.Serve()
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
