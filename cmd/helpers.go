package cmd

import (
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Flag struct {
	Command     *cobra.Command
	Persistent  bool
	Name        string
	ShortHand   string
	Usage       string
	AltDefault  interface{}
	ConfigField string
}

func (f *Flag) Default() interface{} {
	if f.AltDefault == nil && f.ConfigField != "" {
		configDefault := config.DefaultValues[f.ConfigField]
		if configDefault != nil {
			return configDefault
		}
	}
	return f.AltDefault
}

func (f *Flag) Flags() *pflag.FlagSet {
	if f.Persistent {
		return f.Command.PersistentFlags()
	}
	return f.Command.Flags()
}

func RegisterStringFlag(flag *Flag) {
	defaultVal := flag.Default()
	flags := flag.Flags()
	flags.StringP(flag.Name, flag.ShortHand, defaultVal.(string), flag.Usage)
	err := viper.BindPFlag(flag.ConfigField, flags.Lookup(flag.Name))
	if err != nil {
		logr.Fatalf(err.Error())
	}
}

func RegisterIntFlag(flag *Flag) {
	defaultVal := flag.Default()
	flags := flag.Flags()
	flags.IntP(flag.Name, flag.ShortHand, defaultVal.(int), flag.Usage)
	err := viper.BindPFlag(flag.ConfigField, flags.Lookup(flag.Name))
	if err != nil {
		logr.Fatalf(err.Error())
	}
}
