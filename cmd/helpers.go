package cmd

import (
	"os"

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
	AltDefault  any
	ConfigField string
	Required    bool
}

func (f *Flag) Default() any {
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
			logr.Error("failed to mark flag as required", "flag", f.Name, "error", err)
			os.Exit(1)
		}
	}
	if err := viper.BindPFlag(f.ConfigField, f.Flags().Lookup(f.Name)); err != nil {
		logr.Error("failed to bind flag", "flag", f.Name, "error", err)
		os.Exit(1)
	}
}

func (f *Flag) BindString() {
	defaultVal := f.Default()
	s, _ := defaultVal.(string)
	f.Flags().StringP(f.Name, f.ShortHand, s, f.Usage)
	f.bind()
}

func (f *Flag) BindInt() {
	defaultVal := f.Default()
	n, _ := defaultVal.(int)
	f.Flags().IntP(f.Name, f.ShortHand, n, f.Usage)
	f.bind()
}

func (f *Flag) BindStringArray() {
	defaultVal := f.Default()
	arr, _ := defaultVal.([]string)
	f.Flags().StringArrayP(f.Name, f.ShortHand, arr, f.Usage)
	f.bind()
}

func handleError(err error) {
	if err != nil {
		logr.Error(err.Error())
		os.Exit(1)
	}
}
