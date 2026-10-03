package cmd

import (
	"fmt"
	"os"

	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// gencertCmd represents the gencert command
var gencertCmd = &cobra.Command{
	Use:     "gencert",
	Aliases: []string{"gc", "g"},
	Short:   "Generate certificate and private key",
	Run: func(cmd *cobra.Command, args []string) {
		warnLegacyCertExpiry()

		keyFile := viper.GetString(config.CertKeyFile)
		certFile := viper.GetString(config.CertCertificateFile)

		// Both targets are checked before either is written, so a refusal never
		// leaves a half-written pair behind. Overwriting is how an operator
		// loses the identity an in-flight assessment is pinned to.
		force, err := cmd.Flags().GetBool("force")
		handleError(err)
		if !force {
			for _, path := range []string{keyFile, certFile} {
				if _, err := os.Stat(path); err == nil {
					handleError(fmt.Errorf(
						"'%s' already exists, refusing to overwrite it: pass --force to replace the pair",
						path,
					))
				}
			}
		}

		// generate private key
		privKey, err := utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
		handleError(err)
		err = utils.WriteKeyToPem(privKey, keyFile)
		handleError(err)

		// generate certificate
		cert, err := utils.GenerateCertificate(
			privKey,
			viper.GetString(config.CertCaOrg),
			viper.GetString(config.CertCaCountry),
			viper.GetString(config.CertCaState),
			viper.GetString(config.CertCaLocality),
			viper.GetString(config.CertCaAddress),
			viper.GetString(config.CertCaPostcode),
			viper.GetInt(config.CertCaExpDays),
		)
		handleError(err)
		err = utils.WriteCertificateToPem(cert, certFile)
		handleError(err)
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
		ConfigField: config.CertKeyFile,
	}
	f.BindString()
	f = &Flag{
		Command:     gencertCmd,
		Name:        "cert-file",
		ShortHand:   "f",
		Usage:       "certificate output file",
		ConfigField: config.CertCertificateFile,
	}
	f.BindString()
	// Not a Flag: there is no config key behind it, and Flag.bind() requires a
	// ConfigField. Same reason client.go registers --url directly.
	gencertCmd.Flags().BoolP("force", "F", false, "overwrite an existing certificate and key")
}
