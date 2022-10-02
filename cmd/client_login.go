package cmd

import (
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:     "login [link-name]",
	Aliases: []string{"l"},
	Args:    cobra.ExactArgs(1),
	Short:   "Start an idp initiated login flow (opens a browser)",
	Run: func(cmd *cobra.Command, args []string) {
		// get link name from command line args
		link := args[0]
		relayState, err := cmd.Flags().GetString("relay-state")
		handleError(err)

		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		handleError(err)

		// fetch list of shortcut names
		shortcuts, err := c.ShortcutList()
		handleError(err)

		// check if requested link exists
		linkExists := false
		for _, shortcut := range shortcuts {
			if shortcut == link {
				linkExists = true
				break
			}
		}
		if !linkExists {
			logr.Fatalf("link not found: %s", link)
		}

		// build login link
		linkPath := "/login/" + link
		if relayState != "" {
			linkPath += "/" + relayState
		}
		loginLink := viper.GetString(config.BaseUrl) + linkPath

		// open link with browser
		err = browser.OpenURL(loginLink)
		handleError(err)
	},
}

func init() {
	clientCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringP("relay-state", "r", "", "relay state value")
}
