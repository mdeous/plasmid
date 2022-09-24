package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// spdelCmd represents the spGet command
var spdelCmd = &cobra.Command{
	Use:   "sp-del",
	Short: "Delete a service provider",
	Run: func(cmd *cobra.Command, args []string) {
		// get target service from command line
		svc, err := cmd.Flags().GetString("service")
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// delete service
		err = c.ServiceDel(svc)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	clientCmd.AddCommand(spdelCmd)
	spdelCmd.Flags().StringP("service", "s", "", "id of service provider to delete")
	if err := spdelCmd.MarkFlagRequired("service"); err != nil {
		logr.Fatalf(err.Error())
	}
}
