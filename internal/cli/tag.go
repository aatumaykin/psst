package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/store"
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

		isGit := storageIsGit(cmd, global, env)

		if isGit && !store.ValidTag.MatchString(tag) {
			exitWithError(fmt.Sprintf("invalid tag %q. Must match [a-z][a-z0-9-]*", tag))
		}

		v, err := getUnlockedVault(cmd, jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if isGit {
			if tagErr := v.RetagSecret(name, []string{tag}); tagErr != nil {
				exitWithError(tagErr.Error())
			}
		} else if tagErr := v.AddTag(name, tag); tagErr != nil {
			exitWithError(tagErr.Error())
		}

		f.Success(fmt.Sprintf("Tagged %s with %s", name, tag))
	},
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> [tag]",
	Short: "Remove a tag from a secret",
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]

		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		isGit := storageIsGit(cmd, global, env)

		if !isGit && len(args) == 1 {
			exitWithError("tag argument required for sqlite vault")
		}

		v, err := getUnlockedVault(cmd, jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if isGit {
			tag := ""
			if len(args) == 2 {
				tag = args[1]
				sec, getErr := v.GetSecret(name)
				if getErr != nil {
					exitWithError(getErr.Error())
				}
				if sec == nil {
					exitWithError(fmt.Sprintf("secret %q not found", name))
				}
				if len(sec.Tags) != 1 || sec.Tags[0] != tag {
					exitWithError(fmt.Sprintf("secret %s has tag %v, not %q", name, sec.Tags, tag))
				}
			} else {
				sec, getErr := v.GetSecret(name)
				if getErr != nil {
					exitWithError(getErr.Error())
				}
				if sec == nil {
					exitWithError(fmt.Sprintf("secret %q not found", name))
				}
				if len(sec.Tags) == 1 {
					tag = sec.Tags[0]
				}
				if tag == "" {
					exitWithError(fmt.Sprintf("secret %s has no tag", name))
				}
			}
			if tagErr := v.RetagSecret(name, nil); tagErr != nil {
				exitWithError(tagErr.Error())
			}
			f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
			return
		}

		tag := args[1]
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
