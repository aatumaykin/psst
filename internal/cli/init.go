package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new vault",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		vaultPath, err := vault.FindVaultPath(global, env)
		if err != nil {
			exitWithError(err.Error())
		}

		keychainAvailable := keyring.IsKeychainAvailable()
		envPasswordSet := keyring.IsEnvPasswordSet()

		if !keychainAvailable && !envPasswordSet {
			exitWithError("OS keychain unavailable. Set PSST_PASSWORD before running init:\n  export PSST_PASSWORD=\"your-password\"\n  psst init")
		}

		enc := crypto.NewAESGCM()
		kp := keyring.NewProvider(enc)

		opts := vault.InitOptions{
			Global: global,
			Env:    env,
		}

		if err := vault.InitVault(vaultPath, enc, kp, opts); err != nil {
			exitWithError(err.Error())
		}

		f.Success("Vault created at " + vaultPath)

		if !keychainAvailable {
			fmt.Fprintln(os.Stderr, "⚠ Using PSST_PASSWORD (OS keychain unavailable)")
			fmt.Fprintln(os.Stderr, "  Set PSST_PASSWORD before each use:")
			fmt.Fprintln(os.Stderr, "    export PSST_PASSWORD=\"your-password\"")
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
