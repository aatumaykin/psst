package cli

import (
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
			fmt.Printf("Enter value for %s: ", name)
			passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				exitWithError(fmt.Sprintf("Failed to read password: %v", err))
			}
			value = strings.TrimSpace(string(passwordBytes))
		}

		if value == "" {
			exitWithError("Value cannot be empty")
		}

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		if err := v.SetSecret(name, value, tags); err != nil {
			exitWithError(err.Error())
		}

		f.Success(fmt.Sprintf("Secret %s set", name))
	},
}

func init() {
	setCmd.Flags().Bool("stdin", false, "Read value from stdin")
	rootCmd.AddCommand(setCmd)
}
