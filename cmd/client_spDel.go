package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// spDelCmd represents the spGet command
var spDelCmd = &cobra.Command{
	Use:     "sp-del [sp-name]",
	Aliases: []string{"spd"},
	Args:    cobra.ExactArgs(1),
	Short:   "Delete a service provider",
	Run: func(cmd *cobra.Command, args []string) {
		// get target service from command line
		sp := args[0]

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// check if sp exists
		sps, err := c.ServiceList()
		handleError(err)
		if !stringInArray(sp, sps) {
			logr.Fatalf("service provider not found: %s", sp)
		}

		// delete service
		err = c.ServiceDel(sp)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(spDelCmd)
}
