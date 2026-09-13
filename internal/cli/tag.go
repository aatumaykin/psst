package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

var tagCmd = &cobra.Command{
	Use:   "tag <name> <tag>",
	Short: "Add a tag to a secret",
	//nolint:mnd // exact args count for command
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, tag := args[0], args[1]

		if err := requireValidName(name); err != nil {
			return err
		}

		isGit := storageIsGit(getGlobalFlags(cmd))

		if isGit && !store.ValidTag.MatchString(tag) {
			return exitWithError(fmt.Sprintf("invalid tag %q. Must match [a-z][a-z0-9-]*", tag))
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if isGit {
				if tagErr := v.RetagSecret(cmd.Context(), name, []string{tag}); tagErr != nil {
					return exitWithError(tagErr.Error())
				}
			} else if tagErr := v.AddTag(cmd.Context(), name, tag); tagErr != nil {
				return exitWithError(tagErr.Error())
			}
			f.Success(fmt.Sprintf("Tagged %s with %s", name, tag))
			return nil
		})
	},
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> [tag]",
	Short: "Remove a tag from a secret",
	//nolint:mnd // args range for command
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if err := requireValidName(name); err != nil {
			return err
		}

		isGit := storageIsGit(getGlobalFlags(cmd))

		if !isGit && len(args) == 1 {
			return exitWithError("tag argument required for sqlite vault")
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if isGit {
				tag := ""
				if len(args) == 2 {
					tag = args[1]
					sec, getErr := v.GetSecret(cmd.Context(), name)
					if getErr != nil {
						return exitWithError(getErr.Error())
					}
					if sec == nil {
						return exitWithError(fmt.Sprintf("secret %q not found", name))
					}
					if len(sec.Tags) != 1 || sec.Tags[0] != tag {
						return exitWithError(fmt.Sprintf("secret %s has tag %v, not %q", name, sec.Tags, tag))
					}
				} else {
					sec, getErr := v.GetSecret(cmd.Context(), name)
					if getErr != nil {
						return exitWithError(getErr.Error())
					}
					if sec == nil {
						return exitWithError(fmt.Sprintf("secret %q not found", name))
					}
					if len(sec.Tags) == 1 {
						tag = sec.Tags[0]
					}
					if tag == "" {
						return exitWithError(fmt.Sprintf("secret %s has no tag", name))
					}
				}
				if tagErr := v.RetagSecret(cmd.Context(), name, nil); tagErr != nil {
					return exitWithError(tagErr.Error())
				}
				f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
				return nil
			}

			tag := args[1]
			if tagErr := v.RemoveTag(cmd.Context(), name, tag); tagErr != nil {
				return exitWithError(tagErr.Error())
			}
			f.Success(fmt.Sprintf("Removed tag %s from %s", tag, name))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(tagCmd)
	rootCmd.AddCommand(untagCmd)
}
