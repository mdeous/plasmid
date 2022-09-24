package cmd

import (
	idp "github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginAddCmd represents the loginAdd command
var loginAddCmd = &cobra.Command{
	Use:   "login-add",
	Short: "Create a new idp-initiated login",
	Run: func(cmd *cobra.Command, args []string) {
		// read command line arguments
		name, err := cmd.Flags().GetString("name")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		entityId, err := cmd.Flags().GetString("entity-id")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		relayState, err := cmd.Flags().GetString("relay-state")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		var state *string
		state = nil
		if relayState != "" {
			state = &relayState
		}
		urlSuffixRelay, err := cmd.Flags().GetBool("url-suffix-relay")
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// build shortcut object
		sc := &idp.Shortcut{
			Name:                  name,
			ServiceProviderID:     entityId,
			RelayState:            state,
			URISuffixAsRelayState: urlSuffixRelay,
		}
		err = c.ShortcutAdd(sc)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	clientCmd.AddCommand(loginAddCmd)
	loginAddCmd.Flags().StringP("name", "n", "", "link name")
	if err := loginAddCmd.MarkFlagRequired("name"); err != nil {
		logr.Fatalf(err.Error())
	}
	loginAddCmd.Flags().StringP("entity-id", "e", "", "service provider entity id")
	if err := loginAddCmd.MarkFlagRequired("entity-id"); err != nil {
		logr.Fatalf(err.Error())
	}
	loginAddCmd.Flags().StringP("relay-state", "r", "", "value to use as the relay state")
	loginAddCmd.Flags().BoolP("url-suffix-relay", "u", false, "use login url suffix as relay state")
}
