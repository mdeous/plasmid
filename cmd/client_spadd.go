package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

// spaddCmd represents the spAdd command
var spaddCmd = &cobra.Command{
	Use:   "sp-add",
	Short: "Register a new service provider",
	Run: func(cmd *cobra.Command, args []string) {
		// read command line arguments
		service := viper.GetString(config.SPName)
		metadataUrl := viper.GetString(config.SPMetadata)
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// request metadata
		resp, err := http.Get(metadataUrl)
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// read response
		defer func(body io.ReadCloser) {
			_ = body.Close()
		}(resp.Body)
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// create service
		err = c.ServiceAdd(service, data)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	var f *Flag
	clientCmd.AddCommand(spaddCmd)
	f = &Flag{
		Command:     spaddCmd,
		Name:        "service",
		ShortHand:   "s",
		Usage:       "service provider name",
		AltDefault:  "",
		ConfigField: config.SPName,
		Required:    true,
	}
	f.BindString()
	f = &Flag{
		Command:     spaddCmd,
		Name:        "metadata",
		ShortHand:   "m",
		Usage:       "url to fetch the metadata from",
		AltDefault:  "",
		ConfigField: config.SPMetadata,
		Required:    true,
	}
	f.BindString()
}
