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
	Short: "Create a new idp initiated login link",
	Run: func(cmd *cobra.Command, args []string) {
		// read command line arguments
		name, err := cmd.Flags().GetString("name")
		handleError(err)
		entityId, err := cmd.Flags().GetString("entity-id")
		handleError(err)
		relayState, err := cmd.Flags().GetString("relay-state")
		handleError(err)
		var state *string
		state = nil
		if relayState != "" {
			state = &relayState
		}
		urlSuffixRelay, err := cmd.Flags().GetBool("url-suffix-relay")
		handleError(err)
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)
		// build shortcut object
		sc := &idp.Shortcut{
			Name:                  name,
			ServiceProviderID:     entityId,
			RelayState:            state,
			URISuffixAsRelayState: urlSuffixRelay,
		}
		err = c.ShortcutAdd(sc)
		handleError(err)
	},
}

func init() {
	var err error
	clientCmd.AddCommand(loginAddCmd)
	loginAddCmd.Flags().StringP("name", "n", "", "link name")
	err = loginAddCmd.MarkFlagRequired("name")
	handleError(err)
	loginAddCmd.Flags().StringP("entity-id", "e", "", "service provider entity id")
	err = loginAddCmd.MarkFlagRequired("entity-id")
	handleError(err)
	loginAddCmd.Flags().StringP("relay-state", "r", "", "value to use as the relay state")
	loginAddCmd.Flags().BoolP("url-suffix-relay", "u", false, "use login url suffix as relay state")
}
