package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback <name>",
	Short: "Rollback secret to a previous version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		toVersion, _ := cmd.Flags().GetInt("to")

		if err := requireValidName(name); err != nil {
			return err
		}

		if toVersion <= 0 {
			return exitWithError("Specify version with --to <number>")
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if rbErr := v.Rollback(cmd.Context(), name, toVersion); rbErr != nil {
				return exitWithError(rbErr.Error())
			}
			f.Success(fmt.Sprintf("Rolled back %s to v%d", name, toVersion))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rollbackCmd.Flags().Int("to", 0, "Version number to rollback to")
	rootCmd.AddCommand(rollbackCmd)
}
