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

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.DeleteSecret(name); err != nil {
			exitWithError(err.Error())
		}

		f.Success(fmt.Sprintf("Secret %s removed", name))
	},
}

func init() {
	rootCmd.AddCommand(rmCmd)
}
