package cmd

import (
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start an idp initiated login flow (opens a browser)",
	Run: func(cmd *cobra.Command, args []string) {
		// get link name from command line args
		link, err := cmd.Flags().GetString("link")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		println(link)
	},
}

func init() {
	clientCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringP("link", "l", "", "login link name")
	if err := loginCmd.MarkFlagRequired("link"); err != nil {
		logr.Fatalf(err.Error())
	}
}
