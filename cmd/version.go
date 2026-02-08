package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var version = "dev"

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"ver", "v"},
	Short:   "Show program version",
	Run: func(cmd *cobra.Command, args []string) {
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			logr.Error("failed to get verbose flag", "error", err)
			os.Exit(1)
		}
		versionInfo := ""
		if verbose {
			versionInfo = fmt.Sprintf("%s (built with %s for %s-%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		} else {
			versionInfo = version
		}
		fmt.Println(versionInfo)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().BoolP("verbose", "v", false, "display build information")
}
