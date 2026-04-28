package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var setCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Set a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := requireValidName(name); err != nil {
			return err
		}

		tags, _ := cmd.Flags().GetStringArray("tag")
		useStdin, _ := cmd.Flags().GetBool("stdin")

		var value string
		if useStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = scanner.Text()
			}
		} else {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stdout, "Enter value for %s: ", name)
				passwordBytes, readErr := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stdout)
				if readErr != nil {
					return exitWithError(fmt.Sprintf("Failed to read password: %v", readErr))
				}
				value = string(bytes.TrimSpace(passwordBytes))
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			} else {
				reader := bufio.NewReader(os.Stdin)
				line, readErr := reader.ReadString('\n')
				if readErr != nil {
					return exitWithError(fmt.Sprintf("Failed to read input: %v", readErr))
				}
				value = strings.TrimSpace(line)
			}
		}

		if value == "" {
			return exitWithError("Value cannot be empty")
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			valueBytes := []byte(value)
			defer func() {
				for i := range valueBytes {
					valueBytes[i] = 0
				}
			}()
			if setErr := v.SetSecret(cmd.Context(), name, valueBytes, tags); setErr != nil {
				return exitWithError(setErr.Error())
			}
			f.Success(fmt.Sprintf("Secret %s set", name))
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	setCmd.Flags().Bool("stdin", false, "Read value from stdin")
	rootCmd.AddCommand(setCmd)
}
