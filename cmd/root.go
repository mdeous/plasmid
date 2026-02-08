package cmd

import (
	"log/slog"
	"os"

	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
)

var logr = slog.Default()

var rootCmd = &cobra.Command{
	Use:   "plasmid",
	Short: "SAML identity provider",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", config.DefaultFile, "configuration file")
	cobra.OnInitialize(func() {
		config.Init()
		cfgFile, _ := rootCmd.Flags().GetString("config")
		_, statErr := os.Stat(cfgFile)
		if !(cfgFile == config.DefaultFile && os.IsNotExist(statErr)) {
			if err := config.LoadFile(cfgFile); err != nil {
				logr.Error("failed to load configuration file", "file", cfgFile, "error", err)
				os.Exit(1)
			}
		}
	})
}
