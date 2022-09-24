package cmd

import (
	idp "github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// userAddCmd represents the user-add command
var userAddCmd = &cobra.Command{
	Use:   "user-add",
	Short: "Create a new user account",
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
	var f *Flag
	clientCmd.AddCommand(userAddCmd)
	f = &Flag{
		Command:     userAddCmd,
		Name:        "username",
		ShortHand:   "u",
		Usage:       "user handle",
		ConfigField: config.UserUsername,
	}
	f.BindString()
	f = &Flag{
		Command:     userAddCmd,
		Name:        "email",
		ShortHand:   "e",
		Usage:       "user email address",
		ConfigField: config.UserEmail,
	}
	f.BindString()
	f = &Flag{
		Command:     userAddCmd,
		Name:        "password",
		ShortHand:   "p",
		Usage:       "user plaintext password",
		ConfigField: config.UserPassword,
	}
	f.BindString()
	// TODO: support all user fields
}
