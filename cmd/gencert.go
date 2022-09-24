package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// gencertCmd represents the gencert command
var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate certificate and private key",
	Run: func(cmd *cobra.Command, args []string) {
		// generate private key
		privKey, err := utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		err = utils.WriteKeyToPem(privKey, viper.GetString(config.CertKeyFile))

		// generate certificate
		cert, err := utils.GenerateCertificate(
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
		err = utils.WriteCertificateToPem(cert, viper.GetString(config.CertCertificateFile))
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	var err error
	rootCmd.AddCommand(gencertCmd)
	if err = RegisterIntFlag(gencertCmd, false, "key-size", "s", "private key size", 0, config.CertKeySize); err != nil {
		logr.Fatalf(err.Error())
	}
	if err = RegisterStringFlag(gencertCmd, false, "key-file", "k", "private key output file", "key.pem", config.CertKeyFile); err != nil {
		logr.Fatalf(err.Error())
	}
	if err = RegisterStringFlag(gencertCmd, false, "cert-file", "c", "certificate output file", "cert.pem", config.CertCertificateFile); err != nil {
		logr.Fatalf(err.Error())
	}
}
