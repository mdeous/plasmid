package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginDelCmd represents the loginDel command
var loginDelCmd = &cobra.Command{
	Use:     "login-del [login-name]",
	Aliases: []string{"ld"},
	Args:    cobra.ExactArgs(1),
	Short:   "Delete an idp initiated login link",
	Run: func(cmd *cobra.Command, args []string) {
		// get shortcut name from command line args
		name := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// delete shortcut
		err = c.ShortcutDel(name)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(loginDelCmd)
}
