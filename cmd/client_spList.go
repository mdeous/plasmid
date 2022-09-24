package cmd

import (
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// spListCmd represents the serviceList command
var spListCmd = &cobra.Command{
	Use:     "sp-list",
	Aliases: []string{"sps", "sl"},
	Short:   "List service providers",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch services list
		services, err := c.ServiceList()
		handleError(err)

		// display results
		fmt.Println("Service providers:")
		for _, svc := range services {
			fmt.Println("- ", svc)
		}
	},
}

func init() {
	clientCmd.AddCommand(spListCmd)
}
