package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crewjam/saml/samlidp"
	"github.com/mdeous/plasmid/internal/store"
	"github.com/mdeous/plasmid/pkg/config"
	"github.com/mdeous/plasmid/pkg/server"
	"github.com/mdeous/plasmid/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

var serveCmd = &cobra.Command{
	Use:     "serve",
	Aliases: []string{"srv", "s"},
	Short:   "Start SAML IdP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			privKey *rsa.PrivateKey
			cert    *x509.Certificate
			err     error
		)

		keyFile := stringFlagOrConfig(cmd, "key-file", config.CertKeyFile)
		_, err = os.Stat(keyFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Info("generating private key", "file", keyFile)
			privKey, err = utils.GeneratePrivateKey(viper.GetInt(config.CertKeySize))
			if err != nil {
				return err
			}
			if err = utils.WriteKeyToPem(privKey, keyFile); err != nil {
				return err
			}
		} else {
			logr.Info("loading private key", "file", keyFile)
			privKey, err = utils.LoadPrivateKey(keyFile)
			if err != nil {
				return err
			}
		}

		certFile := stringFlagOrConfig(cmd, "cert-file", config.CertCertificateFile)
		_, err = os.Stat(certFile)
		if errors.Is(err, os.ErrNotExist) {
			logr.Info("generating certificate", "file", certFile)
			cert, err = utils.GenerateCertificate(
				privKey,
				viper.GetString(config.CertCaOrg),
				viper.GetString(config.CertCaCountry),
				viper.GetString(config.CertCaState),
				viper.GetString(config.CertCaLocality),
				viper.GetString(config.CertCaAddress),
				viper.GetString(config.CertCaPostcode),
				viper.GetInt(config.CertCaExpYears),
			)
			if err != nil {
				return err
			}
			if err = utils.WriteCertificateToPem(cert, certFile); err != nil {
				return err
			}
		} else {
			logr.Info("loading certificate", "file", certFile)
			cert, err = utils.LoadCertificate(certFile)
			if err != nil {
				return err
			}
		}

		// The two files are stat'd independently, so a surviving certificate
		// beside a missing key leaves a fresh key signing under the old
		// certificate. Every SP rejects every assertion and names no cause, so
		// fail here where both paths are known and can be pointed at.
		if !utils.KeyPairMatches(privKey, cert) {
			return fmt.Errorf(
				"certificate '%s' does not match private key '%s': "+
					"delete both and restart to generate a fresh pair, or run 'plasmid gencert --force'",
				certFile, keyFile,
			)
		}

		// An expired certificate is a legitimate thing to point at an SP, so
		// warn rather than refuse.
		metadataValidDays := viper.GetInt(config.MetadataValidDays)
		if time.Now().After(cert.NotAfter) {
			logr.Warn("certificate has expired", "file", certFile, "not_after", cert.NotAfter)
		} else if metadataValidDays > 0 {
			// Only reachable with an explicit window: the default derives
			// validUntil from NotAfter, so the two cannot disagree.
			// UTC to match what Plasmid.Metadata actually publishes.
			if validUntil := time.Now().UTC().AddDate(0, 0, metadataValidDays); validUntil.After(cert.NotAfter) {
				logr.Warn(
					"metadata advertises validity past the certificate expiry",
					"valid_until", validUntil, "not_after", cert.NotAfter,
				)
			}
		}

		// pre-populate store with default user and optional SP.
		// Wrapped because samlidp.MemoryStore.List is not safe against
		// concurrent writes, and the dashboard polls it while logins run.
		idpStore := store.New(&samlidp.MemoryStore{})

		username := viper.GetString(config.UserUsername)
		logr.Info("registering default user", "username", username)
		password := viper.GetString(config.UserPassword)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %v", err)
		}
		user := samlidp.User{
			Name:              username,
			PlaintextPassword: &password,
			HashedPassword:    hashedPassword,
			Groups:            viper.GetStringSlice(config.UserGroups),
			Email:             viper.GetString(config.UserEmail),
			Surname:           viper.GetString(config.UserLastName),
			GivenName:         viper.GetString(config.UserFirstName),
		}
		if err = idpStore.Put("/users/"+username, &user); err != nil {
			return err
		}

		if metadataSource := viper.GetString(config.SPMetadata); metadataSource != "" {
			metadataBytes, fetchErr := utils.FetchSPMetadata(metadataSource)
			if fetchErr != nil {
				return fetchErr
			}
			services, parseErr := utils.ParseSPServices(viper.GetString(config.SPName), metadataBytes)
			if parseErr != nil {
				return parseErr
			}
			// Written straight to the store rather than through HandlePutService,
			// which does not exist yet; samlidp.New loads them on startup.
			for _, svc := range services {
				logr.Info("registering service provider", "name", svc.Name, "entity_id", svc.Descriptor.EntityID)
				service := samlidp.Service{Name: svc.Name, Metadata: svc.Descriptor}
				if err = idpStore.Put("/services/"+svc.Name, &service); err != nil {
					return err
				}
			}
		}

		// create server
		logr.Info("setting up identity provider")
		baseUrl, err := url.Parse(viper.GetString(config.BaseUrl))
		if err != nil {
			return err
		}
		idp, err := server.New(server.Options{
			Host:                  viper.GetString(config.Host),
			Port:                  viper.GetInt(config.Port),
			AdminHost:             viper.GetString(config.AdminHost),
			AdminPort:             viper.GetInt(config.AdminPort),
			BaseUrl:               baseUrl,
			Key:                   privKey,
			Certificate:           cert,
			Store:                 idpStore,
			Logger:                logr,
			NameIDFormat:          viper.GetString(config.NameIDFormat),
			SignatureMethod:       viper.GetString(config.SignatureMethod),
			IncludeSubjectAddress: viper.GetBool(config.IncludeSubjectAddr),
			SendUnencrypted:       viper.GetBool(config.SendUnencrypted),
			MetadataValidDays:     metadataValidDays,
		})
		if err != nil {
			return err
		}

		// save metadata. An empty path skips the export, leaving GET /metadata
		// as the only way to fetch it, which keeps the working directory clean
		// when the endpoint is all that is wanted.
		if metadataFile := stringFlagOrConfig(cmd, "metadata-file", config.MetadataFile); metadataFile != "" {
			meta, err := idp.Metadata()
			if err != nil {
				return err
			}
			if err = os.WriteFile(metadataFile, meta, 0644); err != nil {
				return err
			}
			logr.Info("metadata saved", "file", metadataFile)
		} else {
			logr.Info("metadata export skipped, serving it on /metadata only")
		}

		// start server with graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return idp.Serve(ctx)
	},
}

func init() {
	var f *Flag
	rootCmd.AddCommand(serveCmd)
	f = &Flag{
		Command:     serveCmd,
		Name:        "host",
		ShortHand:   "H",
		Usage:       "host to listen on",
		ConfigField: config.Host,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "port",
		ShortHand:   "P",
		Usage:       "port to listen on",
		ConfigField: config.Port,
	}
	f.BindInt()
	f = &Flag{
		Command:     serveCmd,
		Name:        "url",
		ShortHand:   "u",
		Usage:       "base url exposing idp",
		ConfigField: config.BaseUrl,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "nameid-format",
		Usage:       "NameID format to put in assertions",
		ConfigField: config.NameIDFormat,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "send-unencrypted",
		Usage:       "send assertions signed but unencrypted from startup, so they are readable in the inspector",
		ConfigField: config.SendUnencrypted,
	}
	f.BindBool()
	f = &Flag{
		Command:     serveCmd,
		Name:        "include-subject-address",
		Usage:       "include the client address in SubjectConfirmationData and SubjectLocality",
		ConfigField: config.IncludeSubjectAddr,
	}
	f.BindBool()
	f = &Flag{
		Command:     serveCmd,
		Name:        "signature-method",
		Usage:       "XML signature algorithm to sign assertions and responses with",
		ConfigField: config.SignatureMethod,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "metadata-file",
		Usage:       "file the IdP metadata document is exported to, empty to skip the export",
		ConfigField: config.MetadataFile,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "metadata-valid-days",
		Usage:       "days the metadata advertises itself valid for, 0 to track the certificate expiry",
		ConfigField: config.MetadataValidDays,
	}
	f.BindInt()
	// cert-file and key-file are registered unbound, and resolved through
	// stringFlagOrConfig. gencert already binds these two config keys and
	// viper.BindPFlag keeps only the last binding, so binding them here —
	// serve.go's init runs after gencert.go's — would silently stop
	// 'gencert -k' and 'gencert -f' from reaching viper. No shorthands either:
	// -f is taken by 'client user-add'.
	serveCmd.Flags().String("cert-file", "", "certificate file to load or generate")
	serveCmd.Flags().String("key-file", "", "private key file to load or generate")
	f = &Flag{
		Command:     serveCmd,
		Name:        "admin-host",
		Usage:       "host to listen on for the dashboard and admin api",
		ConfigField: config.AdminHost,
	}
	f.BindString()
	f = &Flag{
		Command:     serveCmd,
		Name:        "admin-port",
		Usage:       "port to listen on for the dashboard and admin api",
		ConfigField: config.AdminPort,
	}
	f.BindInt()
}
