package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withVault(cmd, func(v vault.VaultInterface, f *output.Formatter) error {
			if migrateErr := v.MigrateKDF(cmd.Context()); migrateErr != nil {
				return exitWithError(fmt.Sprintf("Migration failed: %v", migrateErr))
			}
			f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(migrateCmd)
}
