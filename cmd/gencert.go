package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// gencertCmd represents the gencert command
var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate IdP certificate and private key",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gencert called")
	},
}

func init() {
	rootCmd.AddCommand(gencertCmd)
}
