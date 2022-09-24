package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "user-list",
	Short: "List registered user accounts",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// fetch users list
		users, err := c.UserList()
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// display results as JSON
		data, _ := json.MarshalIndent(*users, "", "  ")
		fmt.Println(string(data))
	},
}

func init() {
	clientCmd.AddCommand(listCmd)
}
