package cmd

import (
	idp "github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/pkg/client"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
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
	var err error
	userCmd.AddCommand(addCmd)
	if err = RegisterStringFlag(addCmd, "url", "U", "Identity provider base URL", "", config.BaseUrl); err != nil {
		logr.Fatalf(err.Error())
	}
	if err = RegisterStringFlag(addCmd, "username", "u", "User handle", "", config.UserUsername); err != nil {
		logr.Fatalf(err.Error())
	}
	if err = RegisterStringFlag(addCmd, "email", "e", "User email address", "", config.UserEmail); err != nil {
		logr.Fatalf(err.Error())
	}
	if err = RegisterStringFlag(addCmd, "password", "p", "User plaintext password", "", config.UserPassword); err != nil {
		logr.Fatalf(err.Error())
	}
}
