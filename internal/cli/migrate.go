package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		v, err := getUnlockedVault(cmd.Context(), jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		if migrateErr := v.MigrateKDF(cmd.Context()); migrateErr != nil {
			return exitWithError(fmt.Sprintf("Migration failed: %v", migrateErr))
		}

		f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(migrateCmd)
}
