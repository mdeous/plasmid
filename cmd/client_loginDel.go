package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginDelCmd represents the loginDel command
var loginDelCmd = &cobra.Command{
	Use:     "login-del",
	Aliases: []string{"ld"},
	Short:   "Delete an idp initiated login link",
	Run: func(cmd *cobra.Command, args []string) {
		// get shortcut name from command line args
		name, err := cmd.Flags().GetString("name")
		handleError(err)
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)
		// delete service
		err = c.ShortcutDel(name)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(loginDelCmd)
	loginDelCmd.Flags().StringP("name", "n", "", "Name of login link to delete")
	err := loginDelCmd.MarkFlagRequired("name")
	handleError(err)
}
