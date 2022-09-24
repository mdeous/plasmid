package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// spDelCmd represents the spGet command
var spDelCmd = &cobra.Command{
	Use:   "sp-del",
	Short: "Delete a service provider",
	Run: func(cmd *cobra.Command, args []string) {
		// get target service from command line
		svc, err := cmd.Flags().GetString("service")
		handleError(err)
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)
		// delete service
		err = c.ServiceDel(svc)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(spDelCmd)
	spDelCmd.Flags().StringP("service", "s", "", "id of service provider to delete")
	err := spDelCmd.MarkFlagRequired("service")
	handleError(err)
}
