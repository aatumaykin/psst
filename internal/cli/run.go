package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/runner"
)

var runCmd = &cobra.Command{
	Use:   "run <command> [args...]",
	Short: "Run a command with all secrets injected",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOut, quiet, global, env, tags := getGlobalFlags(cmd)
		noMask, _ := cmd.Flags().GetBool("no-mask")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		var secrets map[string][]byte
		if len(tags) > 0 {
			secrets, err = v.GetSecretsByTagValues(tags)
		} else {
			secrets, err = v.GetAllSecrets()
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
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	runCmd.Flags().Bool("no-mask", false, "Disable output masking")
	rootCmd.AddCommand(runCmd)
}
