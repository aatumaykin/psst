package cli

import (
	"github.com/spf13/cobra"
	"github.com/user/psst/internal/crypto"
	"github.com/user/psst/internal/keyring"
	"github.com/user/psst/internal/vault"
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
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
