package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback <name>",
	Short: "Rollback secret to a previous version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]
		toVersion, _ := cmd.Flags().GetInt("to")

		if !validName.MatchString(name) {
			return exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		if toVersion <= 0 {
			return exitWithError("Specify version with --to <number>")
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		if rbErr := v.Rollback(name, toVersion); rbErr != nil {
			return exitWithError(rbErr.Error())
		}

		f.Success(fmt.Sprintf("Rolled back %s to v%d", name, toVersion))
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rollbackCmd.Flags().Int("to", 0, "Version number to rollback to")
	rootCmd.AddCommand(rollbackCmd)
}
