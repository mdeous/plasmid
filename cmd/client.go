package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Interact with a running Plasmid instance",
}

func init() {
	var f *Flag
	rootCmd.AddCommand(clientCmd)
	f = &Flag{
		Command:     clientCmd,
		Persistent:  true,
		Name:        "url",
		Usage:       "plasmid instance url",
		ConfigField: config.BaseUrl,
	}
	f.BindString()
}

// TODO: login-del command
// TODO: login  command
