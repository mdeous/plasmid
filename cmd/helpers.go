package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func getFlags(c *cobra.Command, persistent bool) *pflag.FlagSet {
	if persistent {
		return c.PersistentFlags()
	}
	return c.Flags()
}

func RegisterStringFlag(c *cobra.Command, persistent bool, name string, shorthand string, usage string, defaultValue string, configField string) error {
	if defaultValue == "" {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultValue = configDefault.(string)
		}
	}
	flags := getFlags(c, persistent)
	flags.StringP(name, shorthand, defaultValue, usage)
	return viper.BindPFlag(configField, c.Flags().Lookup(name))
}

func RegisterIntFlag(c *cobra.Command, persistent bool, name string, shorthand string, usage string, defaultValue int, configField string) error {
	if defaultValue == 0 {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultValue = configDefault.(int)
		}
	}
	flags := getFlags(c, persistent)
	flags.IntP(name, shorthand, defaultValue, usage)
	return viper.BindPFlag(configField, c.Flags().Lookup(name))
}
