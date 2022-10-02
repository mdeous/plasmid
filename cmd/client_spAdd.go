package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// spAddCmd represents the spAdd command
var spAddCmd = &cobra.Command{
	Use:     "sp-add",
	Aliases: []string{"spadd", "spa"},
	Short:   "Register a new service provider",
	Run: func(cmd *cobra.Command, args []string) {
		// read command line arguments
		service := viper.GetString(config.SPName)
		metadataUrl := viper.GetString(config.SPMetadata)

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// create service
		err = c.ServiceAdd(service, metadataUrl)
		handleError(err)
	},
}

func init() {
	var f *Flag
	clientCmd.AddCommand(spAddCmd)
	f = &Flag{
		Command:     spAddCmd,
		Name:        "service",
		ShortHand:   "s",
		Usage:       "service provider name",
		AltDefault:  "",
		ConfigField: config.SPName,
		Required:    true,
	}
	f.BindString()
	f = &Flag{
		Command:     spAddCmd,
		Name:        "metadata",
		ShortHand:   "m",
		Usage:       "url to fetch the metadata from",
		AltDefault:  "",
		ConfigField: config.SPMetadata,
		Required:    true,
	}
	f.BindString()
}
