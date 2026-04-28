package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import secrets from .env file, stdin, or environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		useStdin, _ := cmd.Flags().GetBool("stdin")
		fromEnv, _ := cmd.Flags().GetBool("from-env")

		var entries map[string][]byte
		var err error

		switch {
		case fromEnv:
			prefix, _ := cmd.Flags().GetString("prefix")
			entries = readFromEnv(prefix)
		case useStdin:
			entries, err = parseEnvFromReader(os.Stdin)
			if err != nil {
				return exitWithError(err.Error())
			}
		default:
			if len(args) > 0 {
				file, openErr := os.Open(args[0])
				if openErr != nil {
					return exitWithError(fmt.Sprintf("Cannot open file: %v", openErr))
				}
				defer file.Close()
				entries, err = parseEnvFromReader(file)
				if err != nil {
					return exitWithError(err.Error())
				}
			} else {
				return exitWithError("Specify a file, --stdin, or --from-env")
			}
		}

		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			count := 0
			for name, value := range entries {
				if nameErr := vault.ValidateSecretName(name); nameErr != nil {
					if !f.IsQuiet() {
						fmt.Fprintf(os.Stderr, "Skipping invalid name: %s\n", name)
					}
					continue
				}
				if setErr := v.SetSecret(cmd.Context(), name, value, nil); setErr != nil {
					return exitWithError(fmt.Sprintf("Failed to set %s: %v", name, setErr))
				}
				count++
			}

			f.Success(fmt.Sprintf("Imported %d secret(s)", count))
			return nil
		})
	},
}

func parseEnvFromReader(r io.Reader) (map[string][]byte, error) {
	entries := make(map[string][]byte)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := parseEnvLine(line)
		if !ok {
			continue
		}
		entries[name] = []byte(value)
	}
	return entries, scanner.Err()
}

func parseEnvLine(line string) (string, string, bool) {
	name, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)

	if len(value) >= 2 { //nolint:mnd // minimum length for matching quote pair
		if value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
			value = strings.ReplaceAll(value, `\"`, `"`)
			value = strings.ReplaceAll(value, `\\`, `\`)
			return name, value, true
		}
		if value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
			return name, value, true
		}
	}

	return name, value, true
}

func readFromEnv(prefix string) map[string][]byte {
	entries := make(map[string][]byte)
	for _, e := range os.Environ() {
		name, value, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		if vault.ValidateSecretName(name) == nil {
			entries[name] = []byte(value)
		}
	}
	return entries
}

//nolint:gochecknoinits // cobra command registration
func init() {
	importCmd.Flags().Bool("stdin", false, "Read from stdin")
	importCmd.Flags().Bool("from-env", false, "Import from environment variables")
	importCmd.Flags().String("prefix", "", "Only import variables with this prefix (e.g. MYAPP_)")
	rootCmd.AddCommand(importCmd)
}
