package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// userdelCmd represents the userDel command
var userdelCmd = &cobra.Command{
	Use:   "user-del",
	Short: "Delete a registered user",
	Run: func(cmd *cobra.Command, args []string) {
		// get target username from command line
		username, err := cmd.Flags().GetString("username")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// delete user
		err = c.UserDel(username)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	clientCmd.AddCommand(userdelCmd)
	userdelCmd.Flags().StringP("username", "u", "", "Handle of user to delete")
	if err := userdelCmd.MarkFlagRequired("username"); err != nil {
		logr.Fatalf(err.Error())
	}
}
