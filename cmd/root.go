package cmd

import (
	"github.com/crewjam/saml/logger"
	"github.com/mdeous/plasmid/pkg/config"
	"os"

	"github.com/spf13/cobra"
)

var logr = logger.DefaultLogger

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "plasmid",
	Short: "SAML identity provider",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(config.Init)
}
