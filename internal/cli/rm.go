package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:     "rm <name>",
	Short:   "Delete a secret",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"remove", "delete"},
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]

		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if delErr := v.DeleteSecret(name); delErr != nil {
			exitWithError(delErr.Error())
		}

		f.Success(fmt.Sprintf("Secret %s removed", name))
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(rmCmd)
}
