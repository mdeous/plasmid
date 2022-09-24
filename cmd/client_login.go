package cmd

import (
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:     "login",
	Aliases: []string{"l"},
	Short:   "Start an idp initiated login flow (opens a browser)",
	Run: func(cmd *cobra.Command, args []string) {
		// get link name from command line args
		link, err := cmd.Flags().GetString("link")
		handleError(err)
		println(link)
	},
}

func init() {
	clientCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringP("link", "l", "", "login link name")
	err := loginCmd.MarkFlagRequired("link")
	handleError(err)
}
