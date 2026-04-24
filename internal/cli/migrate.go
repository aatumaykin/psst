package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/aatumaykin/psst/internal/crypto"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.MigrateKDF(); err != nil {
			exitWithError(fmt.Sprintf("Migration failed: %v", err))
		}

		f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
