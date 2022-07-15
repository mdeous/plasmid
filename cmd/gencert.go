package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/viper"
	"os"
	"path"

	"github.com/spf13/cobra"
)

// gencertCmd represents the gencert command
var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate IdP certificate and private key",
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
	rootCmd.AddCommand(gencertCmd)
	curDir, err := os.Getwd()
	if err != nil {
		logr.Fatalf(err.Error())
	}
	gencertCmd.Flags().IntP("key-size", "s", 2048, "private key size")
	if err = viper.BindPFlag(config.CertKeySize, gencertCmd.Flags().Lookup("key-size")); err != nil {
		logr.Fatalf(err.Error())
	}
	gencertCmd.Flags().StringP("key-file", "k", path.Join(curDir, "key.pem"), "private key output file")
	if err = viper.BindPFlag(config.CertKeyFile, gencertCmd.Flags().Lookup("key-file")); err != nil {
		logr.Fatalf(err.Error())
	}
	gencertCmd.Flags().StringP("cert-file", "c", path.Join(curDir, "cert.pem"), "certificate output file")
	if err = viper.BindPFlag(config.CertCertificateFile, gencertCmd.Flags().Lookup("cert-file")); err != nil {
		logr.Fatalf(err.Error())
	}
}
