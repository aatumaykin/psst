package cli

import (
	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var runCmd = &cobra.Command{
	Use:   "run <command> [args...]",
	Short: "Run a command with all secrets injected",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := getGlobalFlags(cmd)
		noMask, _ := cmd.Flags().GetBool("no-mask")

		return withVault(cmd, func(v vault.Interface, _ *output.Formatter) error {
			return execWithSecrets(cmd.Context(), v, nil, args, execConfig{
				Tags:   cfg.Tags,
				NoMask: noMask,
			})
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	runCmd.Flags().Bool("no-mask", false, "Disable output masking")
	rootCmd.AddCommand(runCmd)
}
