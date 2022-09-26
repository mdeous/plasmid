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
	Use:     "user-get",
	Aliases: []string{"user", "u", "ug"},
	Short:   "Get details about a user account",
	Run: func(cmd *cobra.Command, args []string) {
		// get target user from command line args
		username, err := cmd.Flags().GetString("username")
		if err != nil {
			logr.Fatalf(err.Error())
		}

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch users list
		users, err := c.UserList()
		handleError(err)

		// check if user1 exists
		userExists := false
		for _, sessId := range users {
			if sessId == username {
				userExists = true
				break
			}
		}
		if !userExists {
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
	userGetCmd.Flags().StringP("username", "u", "", "username of the account")
	err := userGetCmd.MarkFlagRequired("username")
	handleError(err)
}
