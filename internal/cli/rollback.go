package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback <name>",
	Short: "Rollback secret to a previous version",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]
		toVersion, _ := cmd.Flags().GetInt("to")

		if toVersion <= 0 {
			exitWithError("Specify version with --to <number>")
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.Rollback(name, toVersion); err != nil {
			exitWithError(err.Error())
		}

		f.Success(fmt.Sprintf("Rolled back %s to v%d", name, toVersion))
	},
}

func init() {
	rollbackCmd.Flags().Int("to", 0, "Version number to rollback to")
	rootCmd.AddCommand(rollbackCmd)
}
