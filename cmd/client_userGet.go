package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// userGetCmd represents the userGet command
var userGetCmd = &cobra.Command{
	Use:     "user-get [username]",
	Aliases: []string{"user", "userget", "u", "ug"},
	Args:    cobra.ExactArgs(1),
	Short:   "Get details about a user account",
	Run: func(cmd *cobra.Command, args []string) {
		// get target user from command line args
		username := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// check if user1 exists
		users, err := c.UserList()
		handleError(err)
		if !stringInArray(username, users) {
			logr.Fatalf("user not found: %s", username)
		}

		// get user info
		user, err := c.UserGet(username)
		handleError(err)
		data, err := json.MarshalIndent(user, "", "  ")
		if err != nil {
			logr.Fatalf("unable to serialize user '%s': %v", username, err)
		}
		fmt.Println(string(data))
	},
}

func init() {
	clientCmd.AddCommand(userGetCmd)
}
