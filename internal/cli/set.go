package cli

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var validName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var setCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Set a secret",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		name := args[0]

		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
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
					exitWithError(fmt.Sprintf("Failed to read password: %v", readErr))
				}
				value = strings.TrimSpace(string(passwordBytes))
			} else {
				reader := bufio.NewReader(os.Stdin)
				line, _ := reader.ReadString('\n')
				value = strings.TrimSpace(line)
			}
		}

		if value == "" {
			exitWithError("Value cannot be empty")
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if setErr := v.SetSecret(name, value, tags); setErr != nil {
			exitWithError(setErr.Error())
		}

		f.Success(fmt.Sprintf("Secret %s set", name))
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	setCmd.Flags().Bool("stdin", false, "Read value from stdin")
	rootCmd.AddCommand(setCmd)
}
