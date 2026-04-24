package cli

import (
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show psst version",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		f.VersionInfo()
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(versionCmd)
}
