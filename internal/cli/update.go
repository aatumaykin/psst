package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/updater"
	"github.com/aatumaykin/psst/internal/version"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update psst to the latest version",
}

var updateCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a newer version is available",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		info, err := updater.CheckForUpdate()
		if err != nil {
			return exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if jsonOut {
			f.PrintJSON(map[string]string{
				"current": version.Version,
				"latest":  info.LatestVersion,
				"update":  strconv.FormatBool(info.IsNewer()),
			})
			return nil
		}

		if quiet {
			if info.IsNewer() {
				fmt.Fprintln(os.Stdout, info.LatestVersion)
			}
			return nil
		}

		fmt.Fprintf(os.Stdout, "Current: v%s\n", info.CurrentVersion)
		fmt.Fprintf(os.Stdout, "Latest:  v%s\n", info.LatestVersion)

		if info.IsNewer() {
			fmt.Fprintf(os.Stdout, "\nUpdate available! Run: psst update install\n")
		} else {
			fmt.Fprintf(os.Stdout, "\nAlready up to date.\n")
		}
		return nil
	},
}

var updateInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Download and install the latest version",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, _, _, _ := getGlobalFlags(cmd)
		_ = getFormatter(jsonOut, quiet)
		force, _ := cmd.Flags().GetBool("force")

		info, err := updater.CheckForUpdate()
		if err != nil {
			return exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if !force && !info.IsNewer() {
			if !quiet {
				fmt.Fprintf(os.Stdout, "Already up to date (v%s). Use --force to reinstall.\n", info.CurrentVersion)
			}
			return nil
		}

		if !quiet {
			fmt.Fprintf(os.Stdout, "Updating from v%s to v%s...\n", info.CurrentVersion, info.LatestVersion)
		}

		if updateErr := updater.PerformUpdate(info, force); updateErr != nil {
			return exitWithError(fmt.Sprintf("Update failed: %v", updateErr))
		}

		if !quiet {
			fmt.Fprintf(os.Stdout, "Successfully updated to v%s!\n", info.LatestVersion)
		}
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	updateInstallCmd.Flags().Bool("force", false, "Reinstall even if already up to date")
	updateCmd.AddCommand(updateCheckCmd)
	updateCmd.AddCommand(updateInstallCmd)
	rootCmd.AddCommand(updateCmd)
}
