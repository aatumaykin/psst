package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history <name>",
	Short: "View secret version history",
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

		entries, err := v.GetHistory(name)
		if err != nil {
			exitWithError(err.Error())
		}

		if len(entries) == 0 {
			if !quiet {
				fmt.Printf("No history for %s\n", name)
			}
			return
		}

		f.HistoryEntries(name, entries)
	},
}

func init() {
	rootCmd.AddCommand(historyCmd)
}
