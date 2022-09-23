package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func RegisterStringFlag(c *cobra.Command, name string, shorthand string, usage string, defaultValue string, configField string) error {
	if defaultValue == "" {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultValue = configDefault.(string)
		}
	}
	c.Flags().StringP(name, shorthand, defaultValue, usage)
	return viper.BindPFlag(configField, c.Flags().Lookup(name))
}

func RegisterIntFlag(c *cobra.Command, name string, shorthand string, usage string, defaultValue int, configField string) error {
	if defaultValue == 0 {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultValue = configDefault.(int)
		}
	}
	c.Flags().IntP(name, shorthand, defaultValue, usage)
	return viper.BindPFlag(configField, c.Flags().Lookup(name))
}
