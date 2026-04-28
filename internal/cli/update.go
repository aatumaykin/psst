package cli

import (
	"fmt"
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
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)

		info, err := updater.CheckForUpdate()
		if err != nil {
			return exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if cfg.JSON {
			f.PrintJSON(map[string]string{
				"current": version.Version,
				"latest":  info.LatestVersion,
				"update":  strconv.FormatBool(info.IsNewer()),
			})
			return nil
		}

		if cfg.Quiet {
			if info.IsNewer() {
				f.Print(info.LatestVersion)
			}
			return nil
		}

		f.Print(fmt.Sprintf("Current: v%s", info.CurrentVersion))
		f.Print(fmt.Sprintf("Latest:  v%s", info.LatestVersion))

		if info.IsNewer() {
			f.Print("\nUpdate available! Run: psst update install")
		} else {
			f.Print("\nAlready up to date.")
		}
		return nil
	},
}

var updateInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Download and install the latest version",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(false, cfg.Quiet)
		force, _ := cmd.Flags().GetBool("force")

		info, err := updater.CheckForUpdate()
		if err != nil {
			return exitWithError(fmt.Sprintf("Update check failed: %v", err))
		}

		if !force && !info.IsNewer() {
			if !cfg.Quiet {
				f.Print(fmt.Sprintf("Already up to date (v%s). Use --force to reinstall.", info.CurrentVersion))
			}
			return nil
		}

		if !cfg.Quiet {
			f.Print(fmt.Sprintf("Updating from v%s to v%s...", info.CurrentVersion, info.LatestVersion))
		}

		if updateErr := updater.PerformUpdate(info, force); updateErr != nil {
			return exitWithError(fmt.Sprintf("Update failed: %v", updateErr))
		}

		if !cfg.Quiet {
			f.Print(fmt.Sprintf("Successfully updated to v%s!", info.LatestVersion))
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
