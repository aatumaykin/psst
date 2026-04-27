package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/vault"
)

var runCmd = &cobra.Command{
	Use:   "run <command> [args...]",
	Short: "Run a command with all secrets injected",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _, _, _, tags := getGlobalFlags(cmd)
		noMask, _ := cmd.Flags().GetBool("no-mask")
		if noMask {
			fmt.Fprintln(os.Stderr, "Warning: output masking is disabled, secrets may appear in output")
		}

		return withVault(cmd, func(v vault.Interface, _ *output.Formatter) error {
			var secrets map[string][]byte
			var err error
			if len(tags) > 0 {
				secrets, err = v.GetSecretsByTagValues(cmd.Context(), tags)
			} else {
				secrets, err = v.GetAllSecrets(cmd.Context())
			}
			if err != nil {
				return exitWithError(err.Error())
			}

			r := getRunner()
			exitCode, err := r.Exec(secrets, args[0], args[1:], runner.ExecOptions{MaskOutput: !noMask})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
			}
			if exitCode != 0 {
				return &exitError{code: exitCode}
			}
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	runCmd.Flags().Bool("no-mask", false, "Disable output masking")
	rootCmd.AddCommand(runCmd)
}
