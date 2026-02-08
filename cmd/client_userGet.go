package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		if !slices.Contains(users, username) {
			logr.Error("user not found", "username", username)
			os.Exit(1)
		}

		// get user info
		user, err := c.UserGet(username)
		handleError(err)
		data, err := json.MarshalIndent(user, "", "  ")
		if err != nil {
			logr.Error("unable to serialize user", "username", username, "error", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	},
}

func init() {
	clientCmd.AddCommand(userGetCmd)
}
