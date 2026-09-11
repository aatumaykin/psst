package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize git vault with remote",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		discardLocal, _ := cmd.Flags().GetBool("discard-local")
		confirm, _ := cmd.Flags().GetBool("confirm")

		envDir, err := vault.FindVaultDir(global, env)
		if err != nil {
			exitWithError(err.Error())
		}

		storage, err := ResolveStorage(getStorageFlag(cmd), envDir)
		if err != nil {
			exitWithError(err.Error())
		}
		if storage != "git" {
			exitWithError("psst sync requires a git vault")
		}

		_, gs, err := OpenVaultStore(envDir, "git", "", false)
		if err != nil {
			exitWithError(err.Error())
		}

		if discardLocal {
			if !confirm && !term.IsTerminal(int(os.Stdin.Fd())) {
				exitWithError("--discard-local requires --confirm in non-interactive use")
			}
			f.Warning("Discarding local changes: unpushed psst commits will be lost")
			if err := gs.DiscardLocal(); err != nil {
				if errors.Is(err, store.ErrNoRemote) {
					f.Warning("Working locally, no remote configured")
					return
				}
				exitWithError(err.Error())
			}
			f.Success("Discarded local changes; clone reset to remote")
			return
		}

		if err := gs.Sync(); err != nil {
			if errors.Is(err, store.ErrNoRemote) {
				f.Warning("Working locally, no remote configured")
				return
			}
			exitWithError(err.Error())
		}
		f.Success("Synchronized with remote")
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	syncCmd.Flags().Bool("discard-local", false, "Discard local unpushed commits and reset to remote")
	syncCmd.Flags().Bool("confirm", false, "Confirm destructive operations in non-interactive use")
	rootCmd.AddCommand(syncCmd)
}
