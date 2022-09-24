package cmd

import (
	"github.com/spf13/cobra"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Interact with a running Plasmid instance",
}

func init() {
	rootCmd.AddCommand(clientCmd)
}
