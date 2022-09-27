package cmd

import (
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// sessionListCmd represents the sessionList command
var sessionListCmd = &cobra.Command{
	Use:     "session-list",
	Aliases: []string{"sessions", "sessionlist", "sl"},
	Short:   "List active user sessions",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch sessions list
		sessions, err := c.SessionList()
		handleError(err)

		// display results
		if len(sessions) > 0 {
			fmt.Println("Sessions:")
			for _, sess := range sessions {
				fmt.Println("- ", sess)
			}
		} else {
			fmt.Println("No sessions")
		}
	},
}

func init() {
	clientCmd.AddCommand(sessionListCmd)
}
