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
	Use:   "login-list",
	Short: "List links for idp initiated login",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// fetch shortcuts list
		shortcuts, err := c.ShortcutList()
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// display results
		fmt.Println("Login links:")
		for _, link := range shortcuts {
			fmt.Println("- ", link)
		}
	},
}

func init() {
	clientCmd.AddCommand(loginListCmd)
}
