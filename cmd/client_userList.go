package cmd

import (
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// userListCmd represents the list command
var userListCmd = &cobra.Command{
	Use:     "user-list",
	Aliases: []string{"users", "ul", "u"},
	Short:   "List user accounts",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch users list
		users, err := c.UserList()
		handleError(err)

		// display results
		if len(users) > 0 {
			fmt.Println("User accounts:")
			for _, username := range users {
				fmt.Println("- " + username)
			}
		} else {
			fmt.Println("No user accounts")
		}
	},
}

func init() {
	clientCmd.AddCommand(userListCmd)
}
