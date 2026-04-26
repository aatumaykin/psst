package cli

import (
	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		vaultPath, err := vault.FindVaultPath(global, env)
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

		enc, kp := createDependencies()

		opts := vault.InitOptions{
			Global: global,
			Env:    env,
		}

		if initErr := vault.InitVault(vaultPath, enc, kp, opts); initErr != nil {
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
