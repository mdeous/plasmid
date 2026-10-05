package cmd

import (
	"fmt"
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

func (f *Flag) BindBool() {
	defaultVal := f.Default()
	b, _ := defaultVal.(bool)
	f.Flags().BoolP(f.Name, f.ShortHand, b, f.Usage)
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

// clientBaseURL returns the URL of the Plasmid instance to talk to. An
// explicit --url flag wins; otherwise the admin listener is used, which is
// where the REST API lives. base_url is not a fallback: it addresses the public
// SAML listener, which does not serve the admin API.
func clientBaseURL(cmd *cobra.Command) string {
	if f := cmd.Flags().Lookup("url"); f != nil && f.Changed {
		return f.Value.String()
	}
	host := viper.GetString(config.AdminHost)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d", host, viper.GetInt(config.AdminPort))
}

// stringFlagOrConfig resolves a flag that deliberately is not bound to viper:
// an explicit flag wins, otherwise the config key does. Needed wherever two
// commands want the same config key, because viper.BindPFlag keeps only the
// last binding — gencert already binds the cert and key paths, so binding them
// again from serve would silently stop gencert's own flags reaching viper.
func stringFlagOrConfig(cmd *cobra.Command, flagName, configKey string) string {
	if f := cmd.Flags().Lookup(flagName); f != nil && f.Changed {
		return f.Value.String()
	}
	return viper.GetString(configKey)
}

// legacyConfigKeys maps a spelling a config file may still carry to the key
// that replaced it. viper ignores an unknown key without a word, so a config
// still using the old name quietly gets the new default instead of the value it
// asked for, and these decide how long the IdP's credentials stay usable and
// where its metadata lands. Entries can go once no old configs are in
// circulation.
var legacyConfigKeys = map[string]string{
	"cert.ca_exp_years":   config.CertCaExpDays,
	"metadata_file":       config.MetadataFile,
	"metadata_valid_days": config.MetadataValidDays,
}

// warnLegacyConfigKeys flags a config file still using a replaced key name.
//
// The check is viper.InConfig rather than viper.IsSet because IsSet consults
// the environment too, and AutomaticEnv's dot-to-underscore replacer maps
// metadata.file onto IDP_METADATA_FILE - the very variable the new key is
// configured with. IsSet would therefore warn on every env-configured run.
// InConfig reads only the parsed file, which is the only place the old spelling
// can still appear.
func warnLegacyConfigKeys() {
	for legacyKey, replacement := range legacyConfigKeys {
		if !viper.InConfig(legacyKey) {
			continue
		}
		logr.Warn(
			"'"+legacyKey+"' is no longer read, use '"+replacement+"' instead",
			replacement, viper.Get(replacement),
		)
	}
}
