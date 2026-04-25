package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var tagCmd = &cobra.Command{
	Use:   "tag <name> <tag>",
	Short: "Add a tag to a secret",
	//nolint:mnd // exact args count for command
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name, tag := args[0], args[1]

		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if tagErr := v.AddTag(name, tag); tagErr != nil {
			exitWithError(tagErr.Error())
		}

		f.Success(fmt.Sprintf("Tagged %s with %s", name, tag))
	},
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> <tag>",
	Short: "Remove a tag from a secret",
	//nolint:mnd // exact args count for command
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name, tag := args[0], args[1]

		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if tagErr := v.RemoveTag(name, tag); tagErr != nil {
			exitWithError(tagErr.Error())
		}

		f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(tagCmd)
	rootCmd.AddCommand(untagCmd)
}
