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
	var f *Flag
	rootCmd.AddCommand(gencertCmd)
	f = &Flag{
		Command:     gencertCmd,
		Name:        "key-size",
		ShortHand:   "s",
		Usage:       "private key size",
		ConfigField: config.CertKeySize,
	}
	f.BindInt()
	f = &Flag{
		Command:     gencertCmd,
		Name:        "key-file",
		ShortHand:   "k",
		Usage:       "private key output file",
		AltDefault:  "key.pem",
		ConfigField: config.CertKeyFile,
	}
	f.BindString()
	f = &Flag{
		Command:     gencertCmd,
		Name:        "cert-file",
		ShortHand:   "c",
		Usage:       "certificate output file",
		AltDefault:  "cert.pem",
		ConfigField: config.CertCertificateFile,
	}
	f.BindString()
}
