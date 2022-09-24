package cmd

import (
	idp "github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// useraddCmd represents the user-add command
var useraddCmd = &cobra.Command{
	Use:   "user-add",
	Short: "Add a new user account",
	Run: func(cmd *cobra.Command, args []string) {
		// create plasmid client
		c, err := client.New(viper.GetString(config.BaseUrl))
		if err != nil {
			logr.Fatalf(err.Error())
		}
		// build user object
		passwd := viper.GetString(config.UserPassword)
		user := &idp.User{
			Name:              viper.GetString(config.UserUsername),
			PlaintextPassword: &passwd,
			Groups:            viper.GetStringSlice(config.UserGroups),
			Email:             viper.GetString(config.UserEmail),
			Surname:           viper.GetString(config.UserLastName),
			GivenName:         viper.GetString(config.UserFirstName),
		}
		// create user
		err = c.UserAdd(user)
		if err != nil {
			logr.Fatalf(err.Error())
		}
	},
}

func init() {
	clientCmd.AddCommand(useraddCmd)
	RegisterStringFlag(&Flag{
		Command:     useraddCmd,
		Name:        "username",
		ShortHand:   "u",
		Usage:       "user handle",
		ConfigField: config.UserUsername,
	})
	RegisterStringFlag(&Flag{
		Command:     useraddCmd,
		Name:        "email",
		ShortHand:   "e",
		Usage:       "user email address",
		ConfigField: config.UserEmail,
	})
	RegisterStringFlag(&Flag{
		Command:     useraddCmd,
		Name:        "password",
		ShortHand:   "p",
		Usage:       "user plaintext password",
		ConfigField: config.UserPassword,
	})
	// TODO: support all user fields
}
