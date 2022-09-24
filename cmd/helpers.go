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

func RegisterStringFlag(c *cobra.Command, persistent bool, name string, shorthand string, usage string, altDefault string, configField string) error {
	defaultVal := altDefault
	if altDefault == "" {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultVal = configDefault.(string)
		}
	}
	flags := getFlags(c, persistent)
	flags.StringP(name, shorthand, defaultVal, usage)
	return viper.BindPFlag(configField, flags.Lookup(name))
}

func RegisterIntFlag(c *cobra.Command, persistent bool, name string, shorthand string, usage string, altDefault int, configField string) error {
	defaultVal := altDefault
	if altDefault == 0 {
		configDefault := config.DefaultValues[configField]
		if configDefault != nil {
			defaultVal = configDefault.(int)
		}
	}
	flags := getFlags(c, persistent)
	flags.IntP(name, shorthand, defaultVal, usage)
	return viper.BindPFlag(configField, flags.Lookup(name))
}
