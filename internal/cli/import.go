package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import secrets from .env file, stdin, or environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		useStdin, _ := cmd.Flags().GetBool("stdin")
		fromEnv, _ := cmd.Flags().GetBool("from-env")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		var entries map[string]string

		switch {
		case fromEnv:
			prefix, _ := cmd.Flags().GetString("prefix")
			if prefix == "" {
				if !quiet {
					fmt.Fprintf(
						os.Stderr,
						"Warning: importing all matching env vars. Use --prefix to filter (e.g. --prefix MYAPP_)\n",
					)
				}
			}
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

		count := 0
		for name, value := range entries {
			if !validName.MatchString(name) {
				if !quiet {
					fmt.Fprintf(os.Stderr, "Skipping invalid name: %s\n", name)
				}
				continue
			}
			if setErr := v.SetSecret(name, []byte(value), nil); setErr != nil {
				return exitWithError(fmt.Sprintf("Failed to set %s: %v", name, setErr))
			}
			count++
		}

		f.Success(fmt.Sprintf("Imported %d secret(s)", count))
		return nil
	},
}

func parseEnvFromReader(r io.Reader) (map[string]string, error) {
	entries := make(map[string]string)
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
		entries[name] = value
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

func readFromEnv(prefix string) map[string]string {
	entries := make(map[string]string)
	for _, e := range os.Environ() {
		name, value, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		if validName.MatchString(name) {
			entries[name] = value
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
