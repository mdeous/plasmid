package cmd

import (
	"github.com/spf13/cobra"
)

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User accounts management",
}

func init() {
	rootCmd.AddCommand(userCmd)
}
