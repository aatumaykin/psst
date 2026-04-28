package cli

import (
	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)

		vaultPath, err := vault.FindVaultPath(cfg.Global, cfg.Env)
		if err != nil {
			return exitWithError(err.Error())
		}

		keychainAvailable := keyring.IsKeychainAvailable()
		envPasswordSet := keyring.IsEnvPasswordSet()

		if !keychainAvailable && !envPasswordSet {
			return exitWithError(
				"OS keychain unavailable. Set PSST_PASSWORD before running init:\n" +
					"  export PSST_PASSWORD=\"your-password\"\n" +
					"  psst init")
		}

		enc := crypto.NewAESGCM()
		kp := keyring.NewProvider(enc)

		opts := vault.InitOptions{
			Global: cfg.Global,
			Env:    cfg.Env,
		}

		if initErr := vault.InitVault(cmd.Context(), vaultPath, enc, kp, opts); initErr != nil {
			return exitWithError(initErr.Error())
		}

		f.Success("Vault created at " + vaultPath)

		if !keychainAvailable {
			f.Warning("Using PSST_PASSWORD (OS keychain unavailable)")
			f.Bullet("Set PSST_PASSWORD before each use:")
			f.Bullet(`export PSST_PASSWORD="your-password"`)
			f.Bullet("Note: PSST_PASSWORD is visible to other users via /proc on shared systems")
		}
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(initCmd)
}
