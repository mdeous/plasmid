package cmd

import (
	"fmt"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// serviceListCmd represents the serviceList command
var splistCmd = &cobra.Command{
	Use:   "sp-list",
	Short: "List registered service providers",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// fetch services list
		services, err := c.ServiceList()
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// display results
		fmt.Println("Service providers:")
		for _, svc := range services {
			fmt.Println("- ", svc)
		}
	},
}

func init() {
	clientCmd.AddCommand(splistCmd)
}
