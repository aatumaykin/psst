package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var historyCmd = &cobra.Command{
	Use:   "history <name>",
	Short: "View secret version history",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]

		if !validName.MatchString(name) {
			return exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		entries, err := v.GetHistory(name)
		if err != nil {
			return exitWithError(err.Error())
		}

		if len(entries) == 0 {
			if !quiet {
				fmt.Fprintf(os.Stdout, "No history for %s\n", name)
			}
			return nil
		}

		f.HistoryEntries(name, toHistoryItems(entries))
		return nil
	},
}

func toHistoryItems(entries []vault.SecretHistoryEntry) []output.HistoryItem {
	items := make([]output.HistoryItem, len(entries))
	for i, e := range entries {
		items[i] = output.HistoryItem{
			Version:    e.Version,
			Tags:       e.Tags,
			ArchivedAt: e.ArchivedAt,
		}
	}
	return items
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(historyCmd)
}
