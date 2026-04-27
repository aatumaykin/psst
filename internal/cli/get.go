package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a secret value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}
		return withVault(cmd, func(v vault.VaultInterface, f *output.Formatter) error {
			sec, err := v.GetSecret(cmd.Context(), name)
			if err != nil {
				return exitWithError(err.Error())
			}
			f.SecretValue(name, string(sec.Value))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(getCmd)
}
