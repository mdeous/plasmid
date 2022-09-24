package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// userDelCmd represents the userDel command
var userDelCmd = &cobra.Command{
	Use:     "user-del",
	Aliases: []string{"ud"},
	Short:   "Delete an user account",
	Run: func(cmd *cobra.Command, args []string) {
		// get target username from command line
		username, err := cmd.Flags().GetString("username")
		handleError(err)

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// delete user
		err = c.UserDel(username)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(userDelCmd)
	userDelCmd.Flags().StringP("username", "u", "", "Handle of user to delete")
	err := userDelCmd.MarkFlagRequired("username")
	handleError(err)
}
