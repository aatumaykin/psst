package cli

import (
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, tags := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if len(tags) > 0 {
			filtered, err := v.GetSecretsByTags(tags)
			if err != nil {
				exitWithError(err.Error())
			}
			f.SecretList(filtered)
			return
		}

		secrets, err := v.ListSecrets()
		if err != nil {
			exitWithError(err.Error())
		}
		f.SecretList(secrets)
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
