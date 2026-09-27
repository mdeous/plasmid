package cmd

import (
	"github.com/spf13/cobra"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:     "client",
	Aliases: []string{"c"},
	Short:   "Interact with a running Plasmid instance",
}

func init() {
	rootCmd.AddCommand(clientCmd)
	// Not bound to viper: serveCmd already binds its own --url flag to the
	// base_url key, and viper.BindPFlag keeps only the last binding. Client
	// subcommands resolve the value through clientBaseURL() instead.
	clientCmd.PersistentFlags().String("url", "", "plasmid instance url")
}
