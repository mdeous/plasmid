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
	var err error
	rootCmd.AddCommand(clientCmd)
	if err = RegisterStringFlag(clientCmd, true, "url", "", "Plasmid instance URL", "", config.BaseUrl); err != nil {
		logr.Fatalf(err.Error())
	}
}
