package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// sessionDelCmd represents the sessionDel command
var sessionDelCmd = &cobra.Command{
	Use:     "session-del [session-id]",
	Aliases: []string{"sessiondel", "sd"},
	Args:    cobra.ExactArgs(1),
	Short:   "Delete an active user session",
	Run: func(cmd *cobra.Command, args []string) {
		// get session id from command line args
		sessionId := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// check if session exists
		sessions, err := c.SessionList()
		handleError(err)
		if !stringInArray(sessionId, sessions) {
			logr.Fatalf("session not found: %s", sessionId)
		}

		// delete session
		// FIXME: depending on the chars in the session id, request fails
		err = c.SessionDel(sessionId)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(sessionDelCmd)
}
