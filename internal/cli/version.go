package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show psst version",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		if f.IsJSON() {
			f.PrintJSON(version.JSON())
			return
		}

		if f.IsQuiet() {
			fmt.Fprint(cmd.OutOrStdout(), version.Version+"\n")
			return
		}

		fmt.Fprint(cmd.OutOrStdout(), version.String()+"\n")
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(versionCmd)
}
