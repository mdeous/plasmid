package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// userListCmd represents the list command
var userListCmd = &cobra.Command{
	Use:   "user-list",
	Short: "List user accounts",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)
		// fetch users list
		users, err := c.UserList()
		handleError(err)
		// display results as JSON
		data, _ := json.MarshalIndent(*users, "", "  ")
		fmt.Println(string(data))
	},
}

func init() {
	clientCmd.AddCommand(userListCmd)
}
