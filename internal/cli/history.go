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
		name := args[0]
		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}
		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			entries, err := v.GetHistory(cmd.Context(), name)
			if err != nil {
				return exitWithError(err.Error())
			}

			if len(entries) == 0 {
				if !f.IsQuiet() {
					fmt.Fprintf(os.Stdout, "No history for %s\n", name)
				}
				return nil
			}

			f.HistoryEntries(name, toHistoryItems(entries))
			return nil
		})
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
