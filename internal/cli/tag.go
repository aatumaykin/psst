package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var tagCmd = &cobra.Command{
	Use:   "tag <name> <tag>",
	Short: "Add a tag to a secret",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name, tag := args[0], args[1]

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.AddTag(name, tag); err != nil {
			exitWithError(err.Error())
		}

		f.Success(fmt.Sprintf("Tagged %s with %s", name, tag))
	},
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> <tag>",
	Short: "Remove a tag from a secret",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name, tag := args[0], args[1]

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.RemoveTag(name, tag); err != nil {
			exitWithError(err.Error())
		}

		f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
	},
}

func init() {
	rootCmd.AddCommand(tagCmd)
	rootCmd.AddCommand(untagCmd)
}
