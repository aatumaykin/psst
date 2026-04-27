package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var rmCmd = &cobra.Command{
	Use:     "rm <name>",
	Short:   "Delete a secret",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"remove", "delete"},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}
		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if delErr := v.DeleteSecret(cmd.Context(), name); delErr != nil {
				return exitWithError(delErr.Error())
			}
			f.Success(fmt.Sprintf("Secret %s removed", name))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(rmCmd)
}
