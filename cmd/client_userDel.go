package cmd

import (
	"os"
	"slices"

	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// userDelCmd represents the userDel command
var userDelCmd = &cobra.Command{
	Use:     "user-del [username]",
	Aliases: []string{"userdel", "ud"},
	Args:    cobra.ExactArgs(1),
	Short:   "Delete an user account",
	Run: func(cmd *cobra.Command, args []string) {
		// get target username from command line
		username := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// check if user exists
		users, err := c.UserList()
		handleError(err)
		if !slices.Contains(users, username) {
			logr.Error("user not found", "username", username)
			os.Exit(1)
		}

		// delete user
		err = c.UserDel(username)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(userDelCmd)
}
