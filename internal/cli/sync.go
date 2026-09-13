package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
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
		acceptRotation, _ := cmd.Flags().GetBool("accept-rotation")
		if acceptRotation && discardLocal {
			exitWithError("--accept-rotation and --discard-local are mutually exclusive")
		}

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

		if acceptRotation {
			if !gs.HasUpstream() {
				f.Warning("Working locally, no remote configured")
				return
			}
			if gs.AheadOfUpstream() {
				exitWithError("cannot accept rotation with unpushed local commits (their values remain in the reflog); run 'psst sync --discard-local' to drop them, then retry — plain 'psst sync' cannot push old-key commits once the rotation has landed")
			}
			meta, err := gs.SyncAcceptRotation()
			if err != nil {
				exitWithError(err.Error())
			}
			probeStore, err := store.NewGitStore(filepath.Join(envDir, "repo"), store.GitOptions{})
			if err != nil {
				exitWithError(fmt.Sprintf("open probe store: %v", err))
			}
			defer probeStore.Close()
			enc := crypto.NewAESGCM()
			pv := vault.New(enc, keyring.NewPasswordProvider(enc, true), probeStore)
			if err := pv.Unlock(); err != nil {
				exitWithError("Failed to unlock vault. Set PSST_PASSWORD to the new password or run in a terminal")
			}
			defer pv.Close()
			metas, err := pv.ListSecrets()
			if err != nil {
				exitWithError(err.Error())
			}
			if len(metas) > 0 {
				if _, err := pv.GetSecret(metas[0].Name); err != nil {
					exitWithError("wrong password or undecryptable secret " + metas[0].Name)
				}
			}
			cfg, err := LoadVaultConfig(envDir)
			if err != nil {
				exitWithError(err.Error())
			}
			cfg.PinSalt = meta.SaltB64
			cfg.PinKDF = meta.Params
			if err := SaveVaultConfig(envDir, *cfg); err != nil {
				exitWithError(err.Error())
			}
			if len(metas) == 0 {
				f.Success("Rotation accepted (vault is empty: password not verified)")
			} else {
				f.Success("Rotation accepted")
			}
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
	syncCmd.Flags().Bool("accept-rotation", false, "Accept a remote key rotation after verifying the new password")
	rootCmd.AddCommand(syncCmd)
}
