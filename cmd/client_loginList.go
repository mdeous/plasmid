package cmd

import (
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// loginListCmd represents the loginList command
var loginListCmd = &cobra.Command{
	Use:     "login-list",
	Aliases: []string{"logins", "loginlist", "ll"},
	Short:   "List links for idp initiated login",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch shortcuts list
		shortcuts, err := c.ShortcutList()
		handleError(err)

		// display results
		if len(shortcuts) > 0 {
			fmt.Println("Login links:")
			for _, link := range shortcuts {
				fmt.Println("- ", link)
			}
		} else {
			fmt.Println("No login links")
		}
	},
}

func init() {
	clientCmd.AddCommand(loginListCmd)
}
