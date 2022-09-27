package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// sessionGetCmd represents the sessionGet command
var sessionGetCmd = &cobra.Command{
	Use:     "session-get [session-id]",
	Aliases: []string{"session", "s", "sg"},
	Args:    cobra.ExactArgs(1),
	Short:   "Get details about an active user session",
	Run: func(cmd *cobra.Command, args []string) {
		// get target session from command line args
		sessionId := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch sessions list
		sessions, err := c.SessionList()
		handleError(err)

		// check if session exists
		sessionExists := false
		for _, sessId := range sessions {
			if sessId == sessionId {
				sessionExists = true
				break
			}
		}
		if !sessionExists {
			logr.Fatalf("session not found: %s", sessionId)
		}

		// get session info
		// FIXME: depending on the chars in the session id, request fails
		session, err := c.SessionGet(sessionId)
		handleError(err)
		data, err := json.MarshalIndent(session, "", "  ")
		if err != nil {
			logr.Fatalf("unable to serialize session '%s': %v", sessionId, err)
		}
		fmt.Println(string(data))
	},
}

func init() {
	clientCmd.AddCommand(sessionGetCmd)
}
