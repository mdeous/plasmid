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
	Required    bool
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

func (f *Flag) bind() {
	if f.Required {
		if err := f.Command.MarkFlagRequired(f.Name); err != nil {
			logr.Fatalf(err.Error())
		}
	}
	err := viper.BindPFlag(f.ConfigField, f.Flags().Lookup(f.Name))
	if err != nil {
		logr.Fatalf(err.Error())
	}
}

func (f *Flag) BindString() {
	defaultVal := f.Default()
	f.Flags().StringP(f.Name, f.ShortHand, defaultVal.(string), f.Usage)
	f.bind()
}

func (f *Flag) BindInt() {
	defaultVal := f.Default()
	f.Flags().IntP(f.Name, f.ShortHand, defaultVal.(int), f.Usage)
	f.bind()
}

func (f *Flag) BindStringArray() {
	defaultVal := f.Default()
	f.Flags().StringArrayP(f.Name, f.ShortHand, defaultVal.([]string), f.Usage)
	f.bind()
}

func handleError(err error) {
	if err != nil {
		logr.Fatalf(err.Error())
	}
}

func stringInArray(resourceId string, knownIds []string) bool {
	for _, rid := range knownIds {
		if rid == resourceId {
			return true
		}
	}
	return false
}
