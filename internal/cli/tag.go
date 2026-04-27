package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var tagCmd = &cobra.Command{
	Use:   "tag <name> <tag>",
	Short: "Add a tag to a secret",
	//nolint:mnd // exact args count for command
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, tag := args[0], args[1]

		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if tagErr := v.AddTag(cmd.Context(), name, tag); tagErr != nil {
				return exitWithError(tagErr.Error())
			}
			f.Success(fmt.Sprintf("Tagged %s with %s", name, tag))
			return nil
		})
	},
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> <tag>",
	Short: "Remove a tag from a secret",
	//nolint:mnd // exact args count for command
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, tag := args[0], args[1]

		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if tagErr := v.RemoveTag(cmd.Context(), name, tag); tagErr != nil {
				return exitWithError(tagErr.Error())
			}
			f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(tagCmd)
	rootCmd.AddCommand(untagCmd)
}
