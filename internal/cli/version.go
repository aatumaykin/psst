package cli

import (
	"runtime"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show psst version",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		f.VersionInfo(output.VersionData{
			Version:   version.Version,
			Commit:    version.Commit,
			Date:      version.Date,
			GoVersion: runtime.Version(),
			OSArch:    runtime.GOOS + "/" + runtime.GOARCH,
		})
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(versionCmd)
}
