package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a secret value",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		sec, err := v.GetSecret(name)
		if err != nil {
			exitWithError(err.Error())
		}
		if sec == nil {
			exitWithError(fmt.Sprintf("Secret %q not found", name))
		}

		f.SecretValue(name, sec.Value)
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
