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
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		noMask, _ := cmd.Flags().GetBool("no-mask")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		secrets, err := v.GetAllSecrets()
		if err != nil {
			exitWithError(err.Error())
		}

		r := getRunner()
		exitCode, err := r.Exec(secrets, args[0], args[1:], runner.ExecOptions{MaskOutput: !noMask})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
		}
		os.Exit(exitCode)
	},
}

func init() {
	runCmd.Flags().Bool("no-mask", false, "Disable output masking")
	rootCmd.AddCommand(runCmd)
}
