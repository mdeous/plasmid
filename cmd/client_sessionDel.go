package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// sessionDelCmd represents the sessionDel command
var sessionDelCmd = &cobra.Command{
	Use:     "session-del",
	Aliases: []string{"sd"},
	Short:   "Delete an active user session",
	Run: func(cmd *cobra.Command, args []string) {
		// get session id from command line args
		sessionId, err := cmd.Flags().GetString("session-id")
		handleError(err)

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// delete session
		// FIXME: depending on the chars in the session id, request fails
		err = c.SessionDel(sessionId)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(sessionDelCmd)
	sessionDelCmd.Flags().StringP("session-id", "s", "", "id of the session to delete")
	err := sessionDelCmd.MarkFlagRequired("session-id")
	handleError(err)
}
